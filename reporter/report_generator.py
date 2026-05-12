"""
Generador de reportes de seguridad IAM.

Hay dos formatos disponibles:
  ConsoleReporter → salida colorizada en terminal, legible para humanos
  JSONReporter    → archivo estructurado, ideal para CI/CD y otras herramientas

ReportGenerator orquesta ambos y es la clase que usa main.py.

Nota sobre colores ANSI:
  Funcionan en macOS, Linux y Windows 10+. Si tu terminal no los soporta
  puedes quitar los códigos de color sin que cambie la lógica del reporte.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List

from analyzer.findings import Finding
from analyzer.severity import Severity

# ─── Códigos de escape ANSI para colores ──────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"    # crítico
ORANGE = "\033[31m"    # alto
YELLOW = "\033[33m"    # medio
BLUE   = "\033[34m"    # bajo
GREEN  = "\033[32m"    # sin hallazgos
CYAN   = "\033[36m"    # cabeceras
GRAY   = "\033[90m"    # metadata secundaria

VERSION = "1.0.0"

# Mapeo de severidad a color y símbolo para el reporte
SEVERITY_STYLE = {
    Severity.CRITICAL: (RED,    "●"),
    Severity.HIGH:     (ORANGE, "●"),
    Severity.MEDIUM:   (YELLOW, "●"),
    Severity.LOW:      (BLUE,   "●"),
}


class ConsoleReporter:
    """
    Genera un reporte formateado con colores ANSI para la terminal.
    Estructura del reporte:
      1. Cabecera con fecha y política analizada
      2. Resumen: tabla de hallazgos por severidad
      3. Detalle de cada hallazgo con descripción y remediación
      4. Pie con conclusión ejecutiva
    """

    def report(self, findings: List[Finding], policy_name: str = "") -> None:
        self._header(policy_name)

        if not findings:
            print(f"\n  {GREEN}{BOLD}✓  No se detectaron problemas de seguridad en esta política.{RESET}\n")
            self._footer_clean()
            return

        self._summary(findings)
        self._details(findings)
        self._footer(findings)

    # ── Secciones ──────────────────────────────────────────────────────────────

    def _header(self, policy_name: str) -> None:
        print(f"\n{CYAN}{'═'*70}{RESET}")
        print(f"{BOLD}{CYAN}   IAM POLICY ANALYZER  ·  Reporte de Seguridad AWS{RESET}")
        print(f"{CYAN}{'═'*70}{RESET}")
        print(f"   Fecha:   {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}")
        if policy_name:
            print(f"   Política: {BOLD}{policy_name}{RESET}")
        print()

    def _summary(self, findings: List[Finding]) -> None:
        """Muestra una tabla de conteo por nivel de severidad."""
        counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in Severity}

        print(f"  {BOLD}RESUMEN  ({len(findings)} hallazgo{'s' if len(findings) != 1 else ''}){RESET}")
        print(f"  {'─'*40}")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            if counts[sev] == 0:
                continue
            color, dot = SEVERITY_STYLE[sev]
            bar = "█" * min(counts[sev], 20)  # máximo 20 bloques para no romper layout
            print(f"  {color}{dot} {sev.label:<10}{RESET}  {counts[sev]:>3}   {color}{bar}{RESET}")
        print(f"  {'─'*40}\n")

    def _details(self, findings: List[Finding]) -> None:
        """Imprime el detalle completo de cada hallazgo."""
        for idx, finding in enumerate(findings, start=1):
            color, dot = SEVERITY_STYLE[finding.severity]

            # ── Título ──────────────────────────────────────────────────────
            print(f"  {BOLD}[{idx:02d}] {color}{dot} {finding.severity.label}{RESET}  {BOLD}{finding.title}{RESET}")
            print(f"       {GRAY}Regla: {finding.rule_id}   Política: {finding.policy_name}"
                  + (f"   SID: {finding.statement_sid}" if finding.statement_sid else "")
                  + f"{RESET}")

            # ── Descripción ─────────────────────────────────────────────────
            print(f"\n       {BOLD}¿Por qué es un riesgo?{RESET}")
            self._wrap(finding.description, indent=7, width=62)

            # ── Acciones / Recursos afectados ───────────────────────────────
            if finding.affected_actions:
                actions_str = self._truncate_list(finding.affected_actions, max_items=5)
                print(f"\n       {BOLD}Acciones afectadas:{RESET}  {color}{actions_str}{RESET}")

            if finding.affected_resources:
                resources_str = self._truncate_list(finding.affected_resources, max_items=3)
                print(f"       {BOLD}Recursos afectados:{RESET}  {resources_str}")

            # ── Remediación ─────────────────────────────────────────────────
            print(f"\n       {BOLD}Remediación:{RESET}")
            self._wrap(finding.remediation, indent=7, width=62)

            print(f"\n  {'─'*66}")

    def _footer(self, findings: List[Finding]) -> None:
        critical_n = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_n     = sum(1 for f in findings if f.severity == Severity.HIGH)
        print()
        if critical_n:
            print(f"  {RED}{BOLD}⚠  {critical_n} hallazgo(s) CRÍTICO(s) requieren acción inmediata.{RESET}")
        if high_n:
            print(f"  {ORANGE}▲  {high_n} hallazgo(s) de severidad ALTA.{RESET}")
        print(f"{CYAN}{'═'*70}{RESET}\n")

    def _footer_clean(self) -> None:
        print(f"{CYAN}{'═'*70}{RESET}\n")

    # ── Utilidades de formato ──────────────────────────────────────────────────

    def _wrap(self, text: str, indent: int, width: int) -> None:
        """Imprime texto con ajuste de línea automático."""
        words = text.split()
        line  = " " * indent
        for word in words:
            if len(line) + len(word) + 1 > indent + width:
                print(line.rstrip())
                line = " " * indent + word + " "
            else:
                line += word + " "
        if line.strip():
            print(line.rstrip())

    @staticmethod
    def _truncate_list(items: List[str], max_items: int) -> str:
        """Muestra hasta max_items elementos; indica cuántos quedan si hay más."""
        preview = items[:max_items]
        suffix  = f" (+{len(items) - max_items} más)" if len(items) > max_items else ""
        return ", ".join(preview) + suffix


class JSONReporter:
    """
    Escribe un reporte en formato JSON.

    Útil para:
      - Integrar con pipelines CI/CD (el exit code de main.py también ayuda)
      - Enviar resultados a un SIEM o dashboard de seguridad
      - Comparar análisis históricos entre versiones de una política
    """

    def report(self, findings: List[Finding], output_path: str) -> None:
        report_data = {
            "tool":         "IAM Policy Analyzer",
            "version":      VERSION,
            "generated_at": datetime.now().isoformat(),
            "summary":      self._summary(findings),
            "findings":     [f.to_dict() for f in findings],
        }

        path = Path(output_path)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report_data, fh, indent=2, ensure_ascii=False)

        print(f"  Reporte JSON guardado en: {BOLD}{path.resolve()}{RESET}")

    @staticmethod
    def _summary(findings: List[Finding]) -> dict:
        return {
            "total":        len(findings),
            "has_critical": any(f.severity == Severity.CRITICAL for f in findings),
            "by_severity": {
                sev.label: sum(1 for f in findings if f.severity == sev)
                for sev in Severity
            },
        }


class ReportGenerator:
    """
    Punto de entrada para la generación de reportes.

    output_format puede ser:
      "console" → solo terminal (default)
      "json"    → solo archivo JSON
      "both"    → ambos formatos
    """

    def __init__(self):
        self._console = ConsoleReporter()
        self._json    = JSONReporter()

    def generate(
        self,
        findings: List[Finding],
        policy_name: str = "",
        output_format: str = "console",
        json_output_path: str = "reporte_iam.json",
    ) -> None:
        if output_format in ("console", "both"):
            self._console.report(findings, policy_name=policy_name)

        if output_format in ("json", "both"):
            self._json.report(findings, output_path=json_output_path)
