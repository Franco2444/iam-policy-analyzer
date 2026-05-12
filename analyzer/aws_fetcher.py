"""
Módulo para obtener políticas IAM desde AWS usando boto3.

Soporta dos modos:
  - Cuenta propia:     AWSFetcher()
  - Cuenta externa:    AWSFetcher.from_assumed_role(role_arn)

El modo cross-account funciona así:
  1. La Lambda de la cuenta de seguridad llama a sts:AssumeRole
  2. AWS devuelve credenciales temporales (15 minutos) de la cuenta destino
  3. Se crea un cliente IAM con esas credenciales temporales
  4. El fetcher opera como si estuviera dentro de esa cuenta

Esto es posible porque cada cuenta destino tiene un SecurityAuditRole
que confía en el rol de la Lambda (trust policy cross-account).
"""

import boto3
from botocore.exceptions import ClientError
from typing import List, Dict


class AWSFetcher:

    def __init__(self, iam_client=None, region_name: str = None):
        """
        iam_client: cliente IAM ya construido (usado por from_assumed_role).
        Si es None, boto3 usa las credenciales del entorno actual.
        """
        self.iam = iam_client or boto3.client("iam", region_name=region_name)

    @classmethod
    def from_assumed_role(cls, role_arn: str, session_name: str = "IAMAnalyzer") -> "AWSFetcher":
        """
        Crea un AWSFetcher con credenciales de otra cuenta AWS.

        Proceso:
          1. Llama a sts:AssumeRole con el ARN del SecurityAuditRole de la cuenta destino
          2. AWS valida que el rol confía en este caller (trust policy)
          3. Devuelve credenciales temporales (AccessKeyId + SecretAccessKey + SessionToken)
          4. Crea el cliente IAM usando esas credenciales temporales

        role_arn:     ARN del rol a asumir, ej: arn:aws:iam::123456789012:role/SecurityAuditRole
        session_name: nombre de la sesión (aparece en CloudTrail para auditoría)
        """
        sts = boto3.client("sts")

        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=900,  # 15 minutos — más que suficiente para escanear una cuenta
        )

        creds = response["Credentials"]

        # Construimos el cliente IAM con las credenciales temporales de la cuenta destino
        iam_client = boto3.client(
            "iam",
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

        return cls(iam_client=iam_client)

    # ── Métodos de fetching ───────────────────────────────────────────────────

    def fetch_customer_policies(self) -> List[Dict]:
        """
        Obtiene políticas creadas por el cliente (Scope=Local).
        Excluye las políticas managed de AWS (Scope=AWS).
        Usa paginación automática para cuentas con muchas políticas.
        """
        policies = []
        paginator = self.iam.get_paginator("list_policies")

        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                document = self._get_policy_document(
                    policy["Arn"],
                    policy["DefaultVersionId"]
                )
                if document:
                    policies.append({
                        "name":     policy["PolicyName"],
                        "arn":      policy["Arn"],
                        "document": document,
                    })

        return policies

    def fetch_attached_to_roles(self) -> List[Dict]:
        """
        Obtiene políticas adjuntas a roles IAM de la cuenta.
        Deduplicadas por ARN — una política adjunta a varios roles aparece una sola vez.
        """
        policies = {}

        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                attached = self.iam.list_attached_role_policies(RoleName=role["RoleName"])
                for policy in attached["AttachedPolicies"]:
                    arn = policy["PolicyArn"]
                    if arn not in policies:
                        try:
                            meta     = self.iam.get_policy(PolicyArn=arn)["Policy"]
                            document = self._get_policy_document(arn, meta["DefaultVersionId"])
                            if document:
                                policies[arn] = {
                                    "name":        policy["PolicyName"],
                                    "arn":         arn,
                                    "document":    document,
                                    "attached_to": [role["RoleName"]],
                                }
                        except ClientError:
                            pass
                    else:
                        policies[arn]["attached_to"].append(role["RoleName"])

        return list(policies.values())

    def fetch_all(self) -> List[Dict]:
        """
        Combina políticas propias + adjuntas a roles, deduplicadas por ARN.
        Método principal que usa la Lambda.
        """
        seen_arns = set()
        result    = []

        for policy in self.fetch_customer_policies():
            if policy["arn"] not in seen_arns:
                seen_arns.add(policy["arn"])
                result.append(policy)

        for policy in self.fetch_attached_to_roles():
            if policy["arn"] not in seen_arns:
                seen_arns.add(policy["arn"])
                result.append(policy)

        return result

    def _get_policy_document(self, policy_arn: str, version_id: str) -> dict:
        """Obtiene el PolicyDocument de una versión específica."""
        try:
            response = self.iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id,
            )
            return response["PolicyVersion"]["Document"]
        except ClientError as exc:
            print(f"[AVISO] No se pudo obtener {policy_arn}: {exc}")
            return None
