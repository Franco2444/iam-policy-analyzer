"""
Analizador principal de políticas IAM.

Flujo completo:
  1. Cargar JSON desde archivo (analyze_file) o recibir dict (analyze_policy)
  2. Validar la estructura básica del PolicyDocument
  3. Por cada Statement en la política, ejecutar TODAS las reglas de rules.py
  4. Asignar el nombre de la política a cada hallazgo
  5. Filtrar por severidad mínima y ordenar de más a menos crítico
  6. Devolver la lista final de Finding

El PolicyAnalyzer no sabe nada de reportes; solo analiza y devuelve hallazgos.
El módulo reporter/ se encarga de presentarlos.
"""

import json
from pathlib import Path
from typing import List, Union

from .findings import Finding
from .rules import ALL_RULES
from .severity import Severity


class PolicyAnalyzer:
    """
    Analiza una o múltiples políticas IAM en busca de overpermissions.

    Ejemplo de uso:
        analyzer = PolicyAnalyzer(min_severity=Severity.HIGH)
        findings = analyzer.analyze_file("mi_politica.json")
        for f in findings:
            print(f.severity.label, f.title)
    """

    def __init__(self, min_severity: Severity = Severity.LOW):
        """
        min_severity: hallazgos con severidad menor se descartan del resultado.
        Por defecto se incluyen todos (LOW).
        """
        self.min_severity = min_severity

    def analyze_file(self, file_path: Union[str, Path]) -> List[Finding]:
        """
        Carga un archivo JSON y lo analiza.

        El archivo puede tener tres formatos válidos:
          A) PolicyDocument directo:
             { "Version": "2012-10-17", "Statement": [...] }

          B) Política con nombre:
             { "PolicyName": "MiPolitica", "PolicyDocument": {...} }

          C) Lista de políticas (A o B):
             [ { "PolicyName": "...", "PolicyDocument": {...} }, ... ]
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Caso C: lista de políticas
        if isinstance(data, list):
            all_findings: List[Finding] = []
            for item in data:
                name = item.get("PolicyName", path.stem)
                doc  = item.get("PolicyDocument", item)
                all_findings.extend(self.analyze_policy(doc, policy_name=name))
            return all_findings

        # Caso B: dict con PolicyName + PolicyDocument
        if "PolicyDocument" in data:
            return self.analyze_policy(
                data["PolicyDocument"],
                policy_name=data.get("PolicyName", path.stem)
            )

        # Caso A: PolicyDocument directo
        return self.analyze_policy(data, policy_name=path.stem)

    def analyze_policy(
        self,
        policy_document: dict,
        policy_name: str = "SinNombre"
    ) -> List[Finding]:
        """
        Analiza un PolicyDocument (dict) ya cargado en memoria.

        policy_document: el dict con Version + Statement
        policy_name:     nombre para incluir en los reportes
        """
        if "Statement" not in policy_document:
            # Política vacía o malformada; no hay nada que analizar
            return []

        statements = policy_document["Statement"]

        # IAM acepta Statement como dict único o como lista de dicts
        if isinstance(statements, dict):
            statements = [statements]

        findings: List[Finding] = []

        for statement in statements:
            for rule_fn in ALL_RULES:
                try:
                    rule_findings = rule_fn(statement)
                    for finding in rule_findings:
                        # El nombre de la política se asigna aquí porque las reglas
                        # no saben en qué política están operando (separación de responsabilidades)
                        finding.policy_name = policy_name
                    findings.extend(rule_findings)
                except Exception as exc:
                    # Un error en una regla no debe detener el análisis de las demás
                    print(f"[AVISO] Error ejecutando {rule_fn.__name__}: {exc}")

        # Aplicamos el filtro de severidad mínima configurado
        findings = [f for f in findings if f.severity.score >= self.min_severity.score]

        # Ordenamos: los hallazgos más críticos primero
        findings.sort(key=lambda f: f.severity.score, reverse=True)

        return findings
