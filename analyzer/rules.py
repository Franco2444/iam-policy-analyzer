"""
Motor de reglas para detección de overpermissions en políticas IAM.

¿Cómo funciona?
  - Cada función check_* recibe un Statement IAM (dict) y devuelve
    una lista de Finding. Si no detecta nada, devuelve lista vacía.
  - ALL_RULES al final del archivo lista todas las funciones activas.
  - El analizador itera ALL_RULES sobre cada Statement automáticamente.

Estructura de un Statement IAM:
{
    "Sid":      "NombreOpcional",          ← identificador del bloque
    "Effect":   "Allow" | "Deny",          ← permite o deniega
    "Action":   "s3:GetObject" | ["..."],  ← acción(es) IAM
    "Resource": "arn:aws:..." | ["..."],   ← recurso(s) afectados
    "Condition": { ... }                   ← (opcional) condiciones extra
}

Nota: NotAction y NotResource son variantes que invierten la selección.
"""

from typing import List
from .findings import Finding
from .severity import Severity


# ─── Constantes ──────────────────────────────────────────────────────────────

# Acciones que permiten escalar privilegios aunque no sean wildcards.
# Un atacante con estas acciones puede otorgarse a sí mismo más permisos.
PRIVILEGE_ESCALATION_ACTIONS = {
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:UpdateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:SetDefaultPolicyVersion",
    "iam:CreatePolicyVersion",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
}

# Servicios cuyo wildcard (*) es especialmente peligroso, con descripción del riesgo.
# Nota: 'iam' se maneja en RULE_004 con un mensaje más específico.
SENSITIVE_SERVICE_WILDCARDS = {
    "sts":           "Permite asumir cualquier rol en la cuenta (escalación total)",
    "s3":            "Permite acceso completo a todos los buckets S3",
    "ec2":           "Permite control total sobre instancias, redes y almacenamiento",
    "rds":           "Permite acceso total a todas las bases de datos RDS",
    "secretsmanager":"Permite leer y modificar todos los secretos de la cuenta",
    "kms":           "Permite usar/administrar todas las claves de cifrado",
    "lambda":        "Permite ejecutar y modificar todas las funciones Lambda",
    "cloudformation":"Permite desplegar o destruir stacks completos",
    "organizations": "Permite modificar la estructura de la organización AWS",
    "sso":           "Permite modificar accesos SSO y asignaciones de permisos",
}

# Verbos que indican una acción de escritura/modificación/destrucción.
# Se usan para clasificar si una acción con Resource:* es HIGH vs MEDIUM.
WRITE_VERBS = {
    "Create", "Delete", "Put", "Update", "Modify", "Attach",
    "Detach", "Set", "Add", "Remove", "Run", "Start", "Stop",
    "Terminate", "Invoke", "Publish", "Write", "Upload", "Send",
    "Reboot", "Reset", "Revoke", "Tag", "Untag", "Restore",
}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _as_list(value) -> list:
    """
    IAM acepta string o lista en Action/Resource.
    Normaliza ambos casos a lista para procesamiento uniforme.
    """
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [value]
    return []


def _sid(statement: dict) -> str:
    """Devuelve el SID del statement o string vacío si no tiene."""
    return statement.get("Sid", "")


def _is_allow(statement: dict) -> bool:
    """
    Solo analizamos statements Allow.
    Un Deny con wildcards es buena práctica (deniega todo), no un problema.
    """
    return statement.get("Effect", "").lower() == "allow"


# ─── Reglas ──────────────────────────────────────────────────────────────────

def check_full_wildcard_admin(statement: dict) -> List[Finding]:
    """
    RULE_001 | CRÍTICO
    Detecta Action=* con Resource=* simultáneamente.
    Es el equivalente exacto de la política AdministratorAccess de AWS.
    """
    if not _is_allow(statement):
        return []

    actions   = _as_list(statement.get("Action", []))
    resources = _as_list(statement.get("Resource", []))

    if "*" in actions and "*" in resources:
        return [Finding(
            rule_id="RULE_001",
            severity=Severity.CRITICAL,
            title="Acceso de administrador total (Action:* + Resource:*)",
            description=(
                "El statement otorga permisos de administrador completo sobre absolutamente "
                "todos los servicios y recursos de la cuenta AWS. Cualquier usuario o rol "
                "con esta política puede crear, modificar, eliminar y acceder a cualquier "
                "recurso, incluyendo credenciales, datos y configuración de red."
            ),
            statement_sid=_sid(statement),
            affected_actions=["*"],
            affected_resources=["*"],
            remediation=(
                "Define las acciones específicas que el rol/usuario necesita. Usa el servicio "
                "IAM Access Analyzer → 'Generate policy' para obtener una política mínima basada "
                "en el uso real de los últimos 90 días. Como punto de partida, reemplaza "
                "Action:* por una lista explícita como ['s3:GetObject', 'logs:PutLogEvents']."
            ),
        )]
    return []


def check_action_wildcard(statement: dict) -> List[Finding]:
    """
    RULE_002 | CRÍTICO
    Detecta Action=* sobre recursos no-wildcard.
    Aunque el recurso esté acotado, permitir todas las acciones incluye
    operaciones destructivas y administrativas no intencionadas.
    """
    if not _is_allow(statement):
        return []

    actions   = _as_list(statement.get("Action", []))
    resources = _as_list(statement.get("Resource", []))

    # Si hay también Resource:* ya lo captura RULE_001; no duplicamos.
    if "*" not in actions or "*" in resources:
        return []

    resource_preview = ", ".join(resources[:3]) + ("..." if len(resources) > 3 else "")
    return [Finding(
        rule_id="RULE_002",
        severity=Severity.CRITICAL,
        title="Wildcard total en acción (Action:*)",
        description=(
            f"Se permiten TODAS las acciones de AWS sobre: {resource_preview}. "
            "Esto incluye operaciones destructivas (Delete*), de administración (Put*Policy) "
            "y de exfiltración de datos que probablemente no son necesarias."
        ),
        statement_sid=_sid(statement),
        affected_actions=["*"],
        affected_resources=resources,
        remediation=(
            "Reemplaza Action:* con la lista mínima de acciones requeridas. "
            "Ejemplo para un bucket S3 de lectura: ['s3:GetObject', 's3:ListBucket']. "
            "Herramienta útil: aws iam simulate-principal-policy para validar el resultado."
        ),
    )]


def check_resource_wildcard(statement: dict) -> List[Finding]:
    """
    RULE_003 | ALTO / MEDIO
    Detecta Resource=* con acciones que no sean wildcards.

    Severidad diferenciada:
      ALTO  → si alguna acción es de escritura/modificación/destrucción
      MEDIO → si todas las acciones son de solo lectura
    """
    if not _is_allow(statement):
        return []

    actions   = _as_list(statement.get("Action", []))
    resources = _as_list(statement.get("Resource", []))

    # No duplicar hallazgos con RULE_001/RULE_002
    if "*" in actions or "*" not in resources:
        return []

    # Clasificamos cada acción según si su verbo implica escritura
    write_actions = []
    read_actions  = []
    for action in actions:
        # "s3:PutObject" → parte después de ":" es "PutObject"
        verb = action.split(":")[-1] if ":" in action else action
        # Un wildcard de servicio (ej: ec2:*) cubre acciones de escritura;
        # se trata como write para evitar clasificarlo erróneamente como solo lectura.
        if verb == "*" or any(verb.startswith(w) for w in WRITE_VERBS):
            write_actions.append(action)
        else:
            read_actions.append(action)

    findings = []

    if write_actions:
        findings.append(Finding(
            rule_id="RULE_003",
            severity=Severity.HIGH,
            title="Acciones de escritura sobre todos los recursos (Resource:*)",
            description=(
                f"Las acciones {write_actions[:3]}{'...' if len(write_actions) > 3 else ''} "
                "se aplican sobre TODOS los recursos de la cuenta (*). Un atacante o error "
                "podría modificar/destruir recursos de producción, backups o de otras aplicaciones."
            ),
            statement_sid=_sid(statement),
            affected_actions=write_actions,
            affected_resources=["*"],
            remediation=(
                "Reemplaza Resource:* por los ARNs específicos. Ejemplo: en lugar de '*' usa "
                "'arn:aws:s3:::mi-bucket-prod/*' para S3, o "
                "'arn:aws:dynamodb:us-east-1:123456789012:table/MiTabla' para DynamoDB. "
                "Usa variables de política (${aws:username}) para limitar dinámicamente por usuario."
            ),
        ))

    # Solo reportamos lectura si no hay escritura (para no duplicar el mismo Statement)
    if read_actions and not write_actions:
        findings.append(Finding(
            rule_id="RULE_003",
            severity=Severity.MEDIUM,
            title="Acciones de lectura sobre todos los recursos (Resource:*)",
            description=(
                "Las acciones de solo lectura se aplican sobre todos los recursos de la cuenta. "
                "Aunque no modifica datos, puede exponer información sensible de recursos "
                "de otras aplicaciones o entornos."
            ),
            statement_sid=_sid(statement),
            affected_actions=read_actions,
            affected_resources=["*"],
            remediation=(
                "Acota Resource a los ARNs específicos que necesita el rol. "
                "Para CloudWatch Logs: 'arn:aws:logs:region:account:log-group:/aws/lambda/mi-app:*'. "
                "Para S3: usa dos entradas, una para el bucket ('arn:aws:s3:::mi-bucket') "
                "y otra para los objetos ('arn:aws:s3:::mi-bucket/*')."
            ),
        ))

    return findings


def check_iam_full_access(statement: dict) -> List[Finding]:
    """
    RULE_004 | CRÍTICO
    Detecta iam:* explícito (acceso total al servicio IAM).

    El acceso total a IAM es extremadamente peligroso porque permite:
    - Crear usuarios administradores nuevos
    - Escalar privilegios propios
    - Comprometer toda la cadena de identidades de la cuenta
    """
    if not _is_allow(statement):
        return []

    actions   = _as_list(statement.get("Action", []))
    resources = _as_list(statement.get("Resource", []))

    # Si ya tiene Action:* fue capturado por RULE_001/RULE_002
    if "*" in actions:
        return []

    iam_wildcards = [a for a in actions if a.lower() == "iam:*"]
    if not iam_wildcards:
        return []

    return [Finding(
        rule_id="RULE_004",
        severity=Severity.CRITICAL,
        title="Acceso total al servicio IAM (iam:*)",
        description=(
            "El permiso iam:* otorga control completo sobre toda la gestión de identidades "
            "y accesos de la cuenta. Con este permiso un atacante puede crear un usuario "
            "administrador, adjuntarle la política AdministratorAccess y comprometer "
            "toda la infraestructura de forma permanente."
        ),
        statement_sid=_sid(statement),
        affected_actions=iam_wildcards,
        affected_resources=resources,
        remediation=(
            "Define solo las acciones IAM necesarias. Para CI/CD que despliega infraestructura: "
            "['iam:PassRole', 'iam:GetRole', 'iam:ListRoles'] con Resource limitado a un path "
            "específico de roles (ej: 'arn:aws:iam::*:role/app/*'). Nunca uses iam:* en roles "
            "de aplicación; resérvalo exclusivamente para administradores humanos con MFA."
        ),
    )]


def check_service_wildcards(statement: dict) -> List[Finding]:
    """
    RULE_005 | ALTO
    Detecta wildcards a nivel de servicio (ej: s3:*, ec2:*, kms:*).
    Dar acceso total a un servicio entero rara vez está justificado.
    """
    if not _is_allow(statement):
        return []

    actions   = _as_list(statement.get("Action", []))
    resources = _as_list(statement.get("Resource", []))

    if "*" in actions:
        return []  # Ya reportado por reglas anteriores

    findings = []
    for action in actions:
        if ":" not in action:
            continue
        service, action_name = action.lower().split(":", 1)
        # Solo interesa si es wildcard de servicio Y está en nuestra lista de sensibles
        if action_name == "*" and service in SENSITIVE_SERVICE_WILDCARDS:
            risk_description = SENSITIVE_SERVICE_WILDCARDS[service]
            findings.append(Finding(
                rule_id="RULE_005",
                severity=Severity.HIGH,
                title=f"Wildcard de servicio sensible: {action}",
                description=(
                    f"'{action}' otorga acceso total al servicio {service.upper()}. "
                    f"{risk_description}. Esto viola el principio de mínimo privilegio "
                    "y amplía significativamente la superficie de ataque."
                ),
                statement_sid=_sid(statement),
                affected_actions=[action],
                affected_resources=resources,
                remediation=(
                    f"Reemplaza '{action}' con las acciones específicas que necesita la aplicación. "
                    f"Consulta los permisos disponibles de {service.upper()} en: "
                    f"https://docs.aws.amazon.com/service-authorization/latest/reference/"
                    f"list_amazon{service}.html"
                ),
            ))

    return findings


def check_privilege_escalation(statement: dict) -> List[Finding]:
    """
    RULE_006 | ALTO
    Detecta acciones conocidas de escalación de privilegios.

    Estas acciones son peligrosas aunque no sean wildcards, porque
    permiten modificar políticas o crear credenciales para obtener
    más permisos de los que originalmente se tienen.
    """
    if not _is_allow(statement):
        return []

    actions   = _as_list(statement.get("Action", []))
    resources = _as_list(statement.get("Resource", []))

    if "*" in actions:
        return []

    found = [a for a in actions if a in PRIVILEGE_ESCALATION_ACTIONS]
    if not found:
        return []

    findings = []

    # sts:AssumeRole con Resource:* merece un mensaje específico y más severo
    if "sts:AssumeRole" in found and "*" in resources:
        findings.append(Finding(
            rule_id="RULE_006",
            severity=Severity.HIGH,
            title="sts:AssumeRole sobre todos los roles (Resource:*)",
            description=(
                "Permite asumir CUALQUIER rol de la cuenta, incluyendo roles de administrador. "
                "Esto otorga acceso de administrador de forma indirecta: el atacante asume "
                "un rol con más permisos y desde allí opera con esos permisos elevados."
            ),
            statement_sid=_sid(statement),
            affected_actions=["sts:AssumeRole"],
            affected_resources=["*"],
            remediation=(
                "Limita Resource a los ARNs exactos de los roles que se necesitan asumir: "
                "'arn:aws:iam::123456789012:role/MiRolEspecifico'. "
                "Considera agregar una condición de MFA obligatoria: "
                "Condition: {Bool: {'aws:MultiFactorAuthPresent': 'true'}}"
            ),
        ))
        found.remove("sts:AssumeRole")

    # Las demás acciones de escalación
    other = [a for a in found if a != "sts:AssumeRole"]
    if other:
        findings.append(Finding(
            rule_id="RULE_006",
            severity=Severity.HIGH,
            title="Acciones de escalación de privilegios detectadas",
            description=(
                f"Las acciones {other} pueden usarse para escalar privilegios. "
                "Por ejemplo, iam:AttachUserPolicy permite a un usuario otorgarse "
                "permisos adicionales adjuntándose cualquier política existente."
            ),
            statement_sid=_sid(statement),
            affected_actions=other,
            affected_resources=resources,
            remediation=(
                "Evalúa si estas acciones son estrictamente necesarias. Si lo son, "
                "acota Resource a los ARNs específicos permitidos y agrega condiciones "
                "(ej: limitar iam:PassRole a roles con un path o nombre específico). "
                "Implementa SCPs en AWS Organizations para establecer un techo de permisos."
            ),
        ))

    return findings


def check_notaction(statement: dict) -> List[Finding]:
    """
    RULE_007 | ALTO
    Detecta el uso de NotAction en statements Allow.

    NotAction es una lógica de lista negra: permite TODO excepto lo especificado.
    Es un error de configuración frecuente porque el autor cree que está
    restringiendo permisos cuando en realidad está otorgando casi todo.

    Uso legítimo de NotAction: en statements Deny para proteger acciones
    administrativas críticas (ej: Deny NotAction:[iam:CreateVirtualMFADevice] → fuerza MFA).
    """
    if not _is_allow(statement):
        return []  # NotAction en Deny puede ser válido

    not_actions = _as_list(statement.get("NotAction", []))
    if not not_actions:
        return []

    preview = ", ".join(not_actions[:3]) + ("..." if len(not_actions) > 3 else "")
    return [Finding(
        rule_id="RULE_007",
        severity=Severity.HIGH,
        title="NotAction en Allow: otorga más permisos de los esperados",
        description=(
            f"NotAction:[{preview}] con Effect:Allow significa que se permiten "
            "TODAS las acciones de AWS excepto las listadas. Esto suele incluir cientos "
            "de acciones no intencionadas en todos los servicios de la cuenta."
        ),
        statement_sid=_sid(statement),
        affected_actions=not_actions,
        affected_resources=_as_list(statement.get("Resource", [])),
        remediation=(
            "Reemplaza NotAction por Action con la lista explícita de las acciones que "
            "SÍ se deben permitir. Si el objetivo es forzar MFA, usa NotAction en un "
            "statement Deny (no Allow): Effect:Deny + NotAction:[sts:GetSessionToken] + "
            "Condition:{BoolIfExists:{'aws:MultiFactorAuthPresent':'false'}}."
        ),
    )]


# ─── Registro de reglas ───────────────────────────────────────────────────────
# PolicyAnalyzer itera esta lista sobre cada Statement.
# Para desactivar una regla temporalmente, coméntala aquí.
ALL_RULES = [
    check_full_wildcard_admin,   # RULE_001: Action:* + Resource:* (admin total)
    check_action_wildcard,       # RULE_002: Action:* sobre recursos específicos
    check_resource_wildcard,     # RULE_003: Resource:* con acciones write/read
    check_iam_full_access,       # RULE_004: iam:* explícito
    check_service_wildcards,     # RULE_005: wildcards de servicio sensibles
    check_privilege_escalation,  # RULE_006: acciones de escalación de privilegios
    check_notaction,             # RULE_007: NotAction en Allow
]
