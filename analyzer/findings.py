"""
Define el modelo de datos para un hallazgo de seguridad.

Un Finding es el resultado de aplicar una regla a un Statement IAM.
Contiene toda la información necesaria para entender el problema
y cómo corregirlo.
"""

from dataclasses import dataclass, field
from typing import List
from .severity import Severity


@dataclass
class Finding:
    """
    Representa un problema de seguridad detectado en una política IAM.

    Atributos:
      rule_id           → identificador de la regla que lo detectó (ej: RULE_001)
      severity          → nivel de riesgo (CRÍTICO / ALTO / MEDIO / BAJO)
      title             → resumen de una línea del problema
      description       → explicación detallada de por qué es un riesgo
      statement_sid     → SID del Statement donde se detectó (puede estar vacío)
      affected_actions  → lista de acciones problemáticas encontradas
      affected_resources→ lista de recursos problemáticos encontrados
      remediation       → pasos concretos para corregir el problema
      policy_name       → nombre de la política (se asigna externamente)
    """
    rule_id: str
    severity: Severity
    title: str
    description: str
    statement_sid: str
    affected_actions: List[str]
    affected_resources: List[str]
    remediation: str
    policy_name: str = field(default="")

    def to_dict(self) -> dict:
        """Serializa el hallazgo a dict para exportar como JSON."""
        return {
            "rule_id":            self.rule_id,
            "severity":           self.severity.label,
            "severity_score":     self.severity.score,
            "title":              self.title,
            "description":        self.description,
            "policy_name":        self.policy_name,
            "statement_sid":      self.statement_sid,
            "affected_actions":   self.affected_actions,
            "affected_resources": self.affected_resources,
            "remediation":        self.remediation,
        }
