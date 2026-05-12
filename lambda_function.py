"""
Entry point de AWS Lambda — IAM Policy Analyzer con soporte multi-cuenta.

Modos de operación:
  Single-cuenta: AUDIT_ROLE_NAME no configurado → escanea solo la cuenta actual
  Multi-cuenta:  AUDIT_ROLE_NAME configurado    → lista todas las cuentas de la
                 organización y asume SecurityAuditRole en cada una

Flujo multi-cuenta:
  1. Organizations API → lista todas las cuentas activas
  2. Para cada cuenta:
       a. sts:AssumeRole → SecurityAuditRole (credenciales temporales 15 min)
       b. AWSFetcher con esas credenciales → obtiene políticas IAM
       c. PolicyAnalyzer → aplica las 7 reglas
       d. CloudReporter → guarda reporte en S3 (un archivo por cuenta)
  3. SNS → email con resumen de TODAS las cuentas

Variables de entorno:
  S3_BUCKET_NAME      → bucket donde se guardan los reportes
  SNS_TOPIC_ARN       → topic para alertas
  MIN_SEVERITY        → severidad mínima (default: low)
  AUDIT_ROLE_NAME     → nombre del rol a asumir en cada cuenta
                        (default: vacío = modo single-cuenta)
                        ejemplo: SecurityAuditRole
"""

import os
import boto3
from typing import List, Dict

from analyzer.aws_fetcher import AWSFetcher
from analyzer.policy_analyzer import PolicyAnalyzer
from analyzer.severity import Severity
from reporter.cloud_reporter import get_cloud_reporter_from_env


def lambda_handler(event, context):
    print("Iniciando IAM Policy Analyzer...")

    min_severity    = Severity.from_string(os.environ.get("MIN_SEVERITY", "low"))
    audit_role_name = os.environ.get("AUDIT_ROLE_NAME", "").strip()
    analyzer        = PolicyAnalyzer(min_severity=min_severity)
    reporter        = get_cloud_reporter_from_env()

    # ── Detectar modo de operación ────────────────────────────────────────────
    if audit_role_name:
        print(f"Modo multi-cuenta activado. Rol de auditoría: {audit_role_name}")
        accounts = _list_organization_accounts()
        print(f"Cuentas encontradas en la organización: {len(accounts)}")
    else:
        # Sin AUDIT_ROLE_NAME → single-cuenta (modo backward compatible)
        print("Modo single-cuenta (AUDIT_ROLE_NAME no configurado)")
        current_id = boto3.client("sts").get_caller_identity()["Account"]
        accounts   = [{"Id": current_id, "Name": "cuenta-actual"}]

    # ── Analizar cada cuenta ──────────────────────────────────────────────────
    results: List[Dict] = []

    for account in accounts:
        account_id   = account["Id"]
        account_name = account["Name"]
        print(f"\n→ Analizando: {account_name} ({account_id})")

        try:
            fetcher = _get_fetcher(account_id, audit_role_name)
            policies = fetcher.fetch_all()
            print(f"  Políticas encontradas: {len(policies)}")

            findings = []
            for policy in policies:
                findings.extend(
                    analyzer.analyze_policy(policy["document"], policy["name"])
                )
            print(f"  Hallazgos: {len(findings)}")

            # Guardamos reporte individual por cuenta en S3
            report_key = reporter.save_to_s3(findings, account_name=account_name)

            results.append({
                "account_id":   account_id,
                "account_name": account_name,
                "findings":     findings,
                "report_key":   report_key,
            })

        except Exception as exc:
            # Si no podemos asumir el rol o hay otro error, lo registramos
            # y continuamos con las demás cuentas
            print(f"  [ERROR] {account_name}: {exc}")
            results.append({
                "account_id":   account_id,
                "account_name": account_name,
                "findings":     [],
                "error":        str(exc),
            })

    # ── Notificación SNS con resumen ──────────────────────────────────────────
    all_findings = [f for r in results for f in r.get("findings", [])]
    has_critical = any(f.severity == Severity.CRITICAL for f in all_findings)

    # Notificamos si hay cualquier hallazgo CRÍTICO o ALTO en cualquier cuenta
    has_high_or_critical = any(
        f.severity in (Severity.CRITICAL, Severity.HIGH)
        for f in all_findings
    )

    if has_high_or_critical:
        if len(results) > 1:
            reporter.notify_sns_multi(results)
        else:
            r = results[0]
            reporter.notify_sns(r["findings"], r.get("report_key", ""))
    else:
        print("\nSin hallazgos críticos ni altos — no se envía alerta SNS.")

    # ── Respuesta ─────────────────────────────────────────────────────────────
    response = {
        "statusCode":       200,
        "accounts_scanned": len(results),
        "accounts_ok":      sum(1 for r in results if not r.get("error")),
        "accounts_error":   sum(1 for r in results if r.get("error")),
        "total_findings":   len(all_findings),
        "has_critical":     has_critical,
    }
    print(f"\nFinalizado: {response}")
    return response


# ── Helpers ───────────────────────────────────────────────────────────────────

def _list_organization_accounts() -> List[Dict]:
    """
    Lista todas las cuentas ACTIVAS de AWS Organizations.
    Requiere organizations:ListAccounts en el rol de la Lambda.

    Si la cuenta no pertenece a una organización, lanza ClientError
    y la Lambda cae al modo single-cuenta.
    """
    org       = boto3.client("organizations")
    accounts  = []
    paginator = org.get_paginator("list_accounts")

    for page in paginator.paginate():
        for account in page["Accounts"]:
            # Solo incluimos cuentas activas (pueden existir cuentas suspendidas)
            if account["Status"] == "ACTIVE":
                accounts.append({
                    "Id":   account["Id"],
                    "Name": account["Name"],
                })

    return accounts


def _get_fetcher(account_id: str, audit_role_name: str) -> AWSFetcher:
    """
    Devuelve el AWSFetcher correcto según si es la cuenta actual o una externa.

    Para la cuenta actual no necesitamos asumir ningún rol —
    la Lambda ya tiene el IAM Role adjunto con los permisos necesarios.
    Para cuentas externas asumimos el SecurityAuditRole via STS.
    """
    current_id = boto3.client("sts").get_caller_identity()["Account"]

    if account_id == current_id or not audit_role_name:
        # Cuenta propia: usamos las credenciales del IAM Role de la Lambda
        return AWSFetcher()
    else:
        # Cuenta externa: asumimos el SecurityAuditRole via STS cross-account
        role_arn = f"arn:aws:iam::{account_id}:role/{audit_role_name}"
        return AWSFetcher.from_assumed_role(role_arn)
