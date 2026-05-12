"""
Tests unitarios para las reglas de detección IAM.

Cada test valida que una regla:
  - Detecta correctamente el patrón problemático (caso positivo)
  - No genera falsos positivos en statements válidos (caso negativo)
  - Asigna la severidad correcta

Correr con:
  python -m unittest discover -s tests -v
  python -m unittest tests.test_rules -v
"""

import unittest
from analyzer.rules import (
    check_full_wildcard_admin,
    check_iam_full_access,
    check_service_wildcards,
    check_action_wildcard,
    check_resource_wildcard,
    check_privilege_escalation,
    check_notaction,
)
from analyzer.severity import Severity


class TestCheckFullWildcardAdmin(unittest.TestCase):
    """Tests para RULE_001: Action:* + Resource:* simultáneos."""

    def test_detecta_admin_total(self):
        """El patrón más peligroso: Action:* con Resource:* debe ser CRÍTICO."""
        statement = {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
        findings = check_full_wildcard_admin(statement)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].rule_id, "RULE_001")

    def test_detecta_admin_con_sid(self):
        """Debe funcionar igual con SID presente."""
        statement = {
            "Sid": "FullAdmin",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
        findings = check_full_wildcard_admin(statement)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].statement_sid, "FullAdmin")

    def test_detecta_action_lista_con_wildcard(self):
        """Action como lista que contiene * también es CRÍTICO."""
        statement = {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "*"],
            "Resource": "*",
        }
        findings = check_full_wildcard_admin(statement)
        self.assertEqual(len(findings), 1)

    def test_ignora_deny(self):
        """Effect:Deny con wildcards no es un problema — es una denegación total."""
        statement = {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        }
        findings = check_full_wildcard_admin(statement)
        self.assertEqual(len(findings), 0)

    def test_sin_resource_wildcard_no_detecta(self):
        """Action:* sin Resource:* no debe activar RULE_001 (lo maneja RULE_002)."""
        statement = {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "arn:aws:s3:::mi-bucket/*",
        }
        findings = check_full_wildcard_admin(statement)
        self.assertEqual(len(findings), 0)

    def test_sin_action_wildcard_no_detecta(self):
        """Resource:* sin Action:* no debe activar RULE_001."""
        statement = {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "*",
        }
        findings = check_full_wildcard_admin(statement)
        self.assertEqual(len(findings), 0)

    def test_statement_bien_escopado_no_detecta(self):
        """Política correctamente configurada no debe generar hallazgos."""
        statement = {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/*",
        }
        findings = check_full_wildcard_admin(statement)
        self.assertEqual(len(findings), 0)


class TestCheckIAMFullAccess(unittest.TestCase):
    """Tests para RULE_004: iam:* explícito."""

    def test_detecta_iam_wildcard(self):
        """iam:* debe ser CRÍTICO."""
        statement = {
            "Effect": "Allow",
            "Action": "iam:*",
            "Resource": "*",
        }
        findings = check_iam_full_access(statement)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.CRITICAL)
        self.assertEqual(findings[0].rule_id, "RULE_004")

    def test_detecta_iam_wildcard_en_lista(self):
        """iam:* dentro de una lista de acciones también debe detectarse."""
        statement = {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "iam:*", "ec2:DescribeInstances"],
            "Resource": "*",
        }
        findings = check_iam_full_access(statement)
        self.assertEqual(len(findings), 1)
        self.assertIn("iam:*", findings[0].affected_actions)

    def test_ignora_deny(self):
        """iam:* en Deny no es un problema."""
        statement = {
            "Effect": "Deny",
            "Action": "iam:*",
            "Resource": "*",
        }
        findings = check_iam_full_access(statement)
        self.assertEqual(len(findings), 0)

    def test_ignora_action_wildcard_total(self):
        """Si ya hay Action:* no duplica (lo maneja RULE_001/002)."""
        statement = {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
        findings = check_iam_full_access(statement)
        self.assertEqual(len(findings), 0)

    def test_acciones_iam_especificas_no_detecta(self):
        """Acciones IAM específicas (no wildcard) no deben activar RULE_004."""
        statement = {
            "Effect": "Allow",
            "Action": ["iam:GetUser", "iam:ListUsers", "iam:GetRole"],
            "Resource": "*",
        }
        findings = check_iam_full_access(statement)
        self.assertEqual(len(findings), 0)

    def test_case_insensitive(self):
        """La detección debe funcionar independientemente del case."""
        statement = {
            "Effect": "Allow",
            "Action": "IAM:*",
            "Resource": "*",
        }
        findings = check_iam_full_access(statement)
        self.assertEqual(len(findings), 1)


class TestCheckServiceWildcards(unittest.TestCase):
    """Tests para RULE_005: wildcards de servicio sensibles (s3:*, ec2:*, etc.)."""

    def test_detecta_s3_wildcard(self):
        """s3:* debe ser ALTO."""
        statement = {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*",
        }
        findings = check_service_wildcards(statement)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].rule_id, "RULE_005")

    def test_detecta_kms_wildcard(self):
        """kms:* (claves de cifrado) debe ser ALTO."""
        statement = {
            "Effect": "Allow",
            "Action": "kms:*",
            "Resource": "*",
        }
        findings = check_service_wildcards(statement)
        self.assertEqual(len(findings), 1)
        self.assertIn("kms", findings[0].affected_actions[0])

    def test_detecta_multiples_wildcards(self):
        """Múltiples wildcards de servicio deben generar un finding por cada uno."""
        statement = {
            "Effect": "Allow",
            "Action": ["s3:*", "ec2:*", "rds:*"],
            "Resource": "*",
        }
        findings = check_service_wildcards(statement)
        self.assertEqual(len(findings), 3)

    def test_ignora_servicio_no_sensible(self):
        """Wildcards de servicios que no están en la lista no deben detectarse."""
        statement = {
            "Effect": "Allow",
            "Action": "cloudwatch:*",
            "Resource": "*",
        }
        findings = check_service_wildcards(statement)
        self.assertEqual(len(findings), 0)

    def test_ignora_accion_especifica(self):
        """s3:GetObject (acción específica) no debe activar RULE_005."""
        statement = {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": "arn:aws:s3:::mi-bucket/*",
        }
        findings = check_service_wildcards(statement)
        self.assertEqual(len(findings), 0)

    def test_ignora_action_wildcard_total(self):
        """Si ya hay Action:* no duplica con RULE_005."""
        statement = {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
        findings = check_service_wildcards(statement)
        self.assertEqual(len(findings), 0)

    def test_ignora_deny(self):
        """s3:* en Deny no genera hallazgo."""
        statement = {
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": "*",
        }
        findings = check_service_wildcards(statement)
        self.assertEqual(len(findings), 0)

    def test_secretsmanager_wildcard(self):
        """secretsmanager:* debe detectarse como sensible."""
        statement = {
            "Effect": "Allow",
            "Action": "secretsmanager:*",
            "Resource": "*",
        }
        findings = check_service_wildcards(statement)
        self.assertEqual(len(findings), 1)


class TestSeverityOrdering(unittest.TestCase):
    """Verifica que el sistema de severidades esté correctamente ordenado."""

    def test_critico_mayor_que_alto(self):
        self.assertGreater(Severity.CRITICAL.score, Severity.HIGH.score)

    def test_alto_mayor_que_medio(self):
        self.assertGreater(Severity.HIGH.score, Severity.MEDIUM.score)

    def test_medio_mayor_que_bajo(self):
        self.assertGreater(Severity.MEDIUM.score, Severity.LOW.score)

    def test_from_string_critico(self):
        self.assertEqual(Severity.from_string("critical"), Severity.CRITICAL)
        self.assertEqual(Severity.from_string("critico"), Severity.CRITICAL)

    def test_from_string_case_insensitive(self):
        self.assertEqual(Severity.from_string("HIGH"), Severity.HIGH)
        self.assertEqual(Severity.from_string("ALTO"), Severity.HIGH)


if __name__ == "__main__":
    unittest.main(verbosity=2)
