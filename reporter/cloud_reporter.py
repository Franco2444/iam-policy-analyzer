"""
Reporter para infraestructura cloud: S3 + SNS con soporte multi-cuenta.

Modos:
  - Cuenta única:   save_to_s3(findings)
  - Multi-cuenta:   save_to_s3(findings, account_name="produccion")
                    notify_sns_multi(results)  ← resumen por cuenta

Estructura de S3:
  reports/
    2026/05/12/
      cuenta-produccion.json
      cuenta-desarrollo.json
      cuenta-staging.json
"""

import boto3
import json
import os
from datetime import datetime
from typing import List, Dict, Optional

from analyzer.findings import Finding
from analyzer.severity import Severity


class CloudReporter:

    def __init__(self, bucket_name: str, sns_topic_arn: str):
        self.s3            = boto3.client("s3")
        self.sns           = boto3.client("sns")
        self.bucket_name   = bucket_name
        self.sns_topic_arn = sns_topic_arn

    # ── S3 ────────────────────────────────────────────────────────────────────

    def save_to_s3(self, findings: List[Finding], account_name: Optional[str] = None) -> str:
        """
        Guarda el reporte en S3.

        En modo multi-cuenta, cada cuenta tiene su propio archivo:
          reports/2026/05/12/produccion.json
          reports/2026/05/12/desarrollo.json

        En modo single-cuenta:
          reports/2026/05/12/reporte.json
        """
        timestamp  = datetime.utcnow()
        filename   = f"{account_name}.json" if account_name else "reporte.json"
        key        = timestamp.strftime(f"reports/%Y/%m/%d/{filename}")

        report_data = {
            "tool":         "IAM Policy Analyzer",
            "version":      "1.0.0",
            "generated_at": timestamp.isoformat() + "Z",
            "account":      account_name or "unknown",
            "summary":      self._build_summary(findings),
            "findings":     [f.to_dict() for f in findings],
        }

        self.s3.put_object(
            Bucket=self.bucket_name,
            Key=key,
            Body=json.dumps(report_data, indent=2, ensure_ascii=False),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )

        print(f"  [{account_name or 'single'}] Reporte → s3://{self.bucket_name}/{key}")
        return key

    # ── SNS ───────────────────────────────────────────────────────────────────

    def notify_sns(self, findings: List[Finding], report_key: str) -> None:
        """Alerta SNS para modo single-cuenta."""
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        high     = [f for f in findings if f.severity == Severity.HIGH]

        lines = [
            "=" * 60,
            "  IAM POLICY ANALYZER — ALERTA DE SEGURIDAD",
            "=" * 60,
            f"  Fecha:            {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"  Total hallazgos:  {len(findings)}",
            f"  CRÍTICOS:         {len(critical)}",
            f"  ALTOS:            {len(high)}",
            f"  Reporte:          s3://{self.bucket_name}/{report_key}",
            "", "HALLAZGOS CRÍTICOS:", "─" * 60,
        ]

        for f in critical:
            lines += [
                f"  [{f.rule_id}] {f.title}",
                f"  Política: {f.policy_name}",
                f"  Remediación: {f.remediation[:120]}...", "",
            ]

        self.sns.publish(
            TopicArn=self.sns_topic_arn,
            Subject=f"⚠ IAM Analyzer: {len(critical)} hallazgo(s) CRÍTICO(s)",
            Message="\n".join(lines),
        )
        print(f"Alerta SNS enviada — CRÍTICOS: {len(critical)}")

    def notify_sns_multi(self, results: List[Dict]) -> None:
        """
        Alerta SNS para modo multi-cuenta.

        results: lista de dicts con keys:
          account_id, account_name, findings, report_key, error (opcional)

        El email resume todas las cuentas en un solo mensaje,
        ordenadas de más a menos crítica.
        """
        # Construimos el resumen por cuenta
        account_summaries = []
        for r in results:
            findings = r.get("findings", [])
            account_summaries.append({
                "name":     r["account_name"],
                "id":       r["account_id"],
                "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high":     sum(1 for f in findings if f.severity == Severity.HIGH),
                "medium":   sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "total":    len(findings),
                "key":      r.get("report_key", ""),
                "error":    r.get("error", ""),
            })

        # Ordenamos: primero las cuentas con más CRÍTICOS
        account_summaries.sort(key=lambda x: (x["critical"], x["high"]), reverse=True)

        total_findings = sum(s["total"]    for s in account_summaries)
        total_critical = sum(s["critical"] for s in account_summaries)
        total_high     = sum(s["high"]     for s in account_summaries)
        cuentas_con_criticos = sum(1 for s in account_summaries if s["critical"] > 0)
        cuentas_con_error    = sum(1 for s in account_summaries if s["error"])

        lines = [
            "=" * 65,
            "  IAM POLICY ANALYZER — ALERTA MULTI-CUENTA",
            "=" * 65,
            f"  Fecha:                   {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"  Cuentas escaneadas:      {len(account_summaries)}",
            f"  Cuentas con CRÍTICOS:    {cuentas_con_criticos}",
            f"  Total hallazgos:         {total_findings}",
            f"  CRÍTICOS (total):        {total_critical}",
            f"  ALTOS (total):           {total_high}",
        ]

        if cuentas_con_error:
            lines.append(f"  Cuentas con error:       {cuentas_con_error} (sin acceso o rol no configurado)")

        lines += ["", "DETALLE POR CUENTA:", "─" * 65]

        for s in account_summaries:
            if s["error"]:
                lines.append(f"  ✗ {s['name']} ({s['id']})")
                lines.append(f"    Error: {s['error'][:80]}")
            elif s["total"] == 0:
                lines.append(f"  ✓ {s['name']} ({s['id']}) — sin hallazgos")
            else:
                prefix = "⚠" if s["critical"] > 0 else "▲"
                lines.append(f"  {prefix} {s['name']} ({s['id']})")
                lines.append(
                    f"    CRÍTICO: {s['critical']}  ALTO: {s['high']}  MEDIO: {s['medium']}"
                )
                if s["key"]:
                    lines.append(f"    s3://{self.bucket_name}/{s['key']}")
            lines.append("")

        self.sns.publish(
            TopicArn=self.sns_topic_arn,
            Subject=(
                f"⚠ IAM Analyzer: {total_critical} CRÍTICO(s) en "
                f"{cuentas_con_criticos}/{len(account_summaries)} cuentas"
            ),
            Message="\n".join(lines),
        )
        print(f"Alerta SNS multi-cuenta enviada — {cuentas_con_criticos} cuentas con CRÍTICOS")

    @staticmethod
    def _build_summary(findings: List[Finding]) -> dict:
        return {
            "total":        len(findings),
            "has_critical": any(f.severity == Severity.CRITICAL for f in findings),
            "by_severity": {
                sev.label: sum(1 for f in findings if f.severity == sev)
                for sev in Severity
            },
        }


def get_cloud_reporter_from_env() -> CloudReporter:
    """Lee la configuración desde variables de entorno (inyectadas por Lambda)."""
    return CloudReporter(
        bucket_name=os.environ["S3_BUCKET_NAME"],
        sns_topic_arn=os.environ["SNS_TOPIC_ARN"],
    )
