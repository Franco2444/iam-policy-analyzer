#!/usr/bin/env python3
"""
IAM Policy Analyzer - Herramienta de análisis de seguridad para políticas AWS IAM

Detecta:
  ● Wildcards peligrosos (Action:*, Resource:*)
  ● Acceso administrativo total o a servicios sensibles
  ● Acciones de escalación de privilegios
  ● Uso incorrecto de NotAction

Modos de uso:
  Archivo local:
    python main.py -f data/sample_policies.json
    python main.py -f mi_politica.json --output both

  Cuenta AWS real (requiere boto3 y credenciales configuradas):
    python main.py --aws
    python main.py --aws --min-severity high --output both

Exit codes (útil en pipelines CI/CD):
    0 → sin hallazgos críticos
    1 → se detectaron hallazgos CRÍTICOS → bloquear el pipeline
"""

import argparse
import sys
from pathlib import Path

from analyzer.policy_analyzer import PolicyAnalyzer
from analyzer.severity import Severity
from reporter.report_generator import ReportGenerator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analiza políticas IAM de AWS en busca de overpermissions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  Analizar archivo local:
    python main.py -f data/sample_policies.json

  Analizar tu cuenta AWS real directamente:
    python main.py --aws

  Solo críticos y altos, guardar JSON también:
    python main.py --aws --min-severity high --output both
        """
    )

    # Fuente de datos: archivo local O cuenta AWS (mutuamente excluyentes)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "-f", "--file",
        metavar="ARCHIVO",
        help="Archivo JSON local con la(s) política(s) IAM a analizar"
    )
    source.add_argument(
        "--aws",
        action="store_true",
        help="Conectarse a AWS y analizar las políticas reales de la cuenta"
    )

    parser.add_argument(
        "-o", "--output",
        choices=["console", "json", "both"],
        default="console",
        help="Formato de salida: console (default), json, o both"
    )
    parser.add_argument(
        "--json-output",
        default="reporte_iam.json",
        metavar="ARCHIVO",
        help="Nombre del archivo de salida JSON (default: reporte_iam.json)"
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low"],
        default="low",
        dest="min_severity",
        help="Severidad mínima a reportar (default: low = todas)"
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    severity_map = {
        "critical": Severity.CRITICAL,
        "high":     Severity.HIGH,
        "medium":   Severity.MEDIUM,
        "low":      Severity.LOW,
    }
    min_severity = severity_map[args.min_severity]
    analyzer     = PolicyAnalyzer(min_severity=min_severity)

    # ── Modo --aws: obtiene las políticas directamente de la cuenta AWS ───────
    if args.aws:
        try:
            from analyzer.aws_fetcher import AWSFetcher
        except ImportError:
            print("\nError: boto3 no está instalado. Corré: pip3 install boto3\n", file=sys.stderr)
            sys.exit(2)

        print("Conectando a AWS y obteniendo políticas IAM...")
        try:
            fetcher  = AWSFetcher()
            policies = fetcher.fetch_all()
        except Exception as exc:
            print(f"\nError al conectar con AWS: {exc}\n", file=sys.stderr)
            sys.exit(2)

        print(f"Políticas encontradas: {len(policies)}. Analizando...\n")

        findings = []
        for policy in policies:
            findings.extend(
                analyzer.analyze_policy(policy["document"], policy["name"])
            )

        policy_label = "cuenta-aws-real"

    # ── Modo --file: lee desde un archivo JSON local ──────────────────────────
    else:
        try:
            findings = analyzer.analyze_file(args.file)
        except FileNotFoundError as exc:
            print(f"\nError: {exc}\n", file=sys.stderr)
            sys.exit(2)
        except Exception as exc:
            print(f"\nError inesperado: {exc}\n", file=sys.stderr)
            sys.exit(2)

        policy_label = Path(args.file).stem

    # ── Generar reporte ───────────────────────────────────────────────────────
    ReportGenerator().generate(
        findings=findings,
        policy_name=policy_label,
        output_format=args.output,
        json_output_path=args.json_output,
    )

    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
