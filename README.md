# IAM Policy Analyzer

Herramienta de seguridad para AWS que analiza políticas IAM en busca de overpermissions, wildcards peligrosos y acciones de escalación de privilegios.

## ¿Qué detecta?

| Regla | Descripción | Severidad |
|---|---|---|
| RULE_001 | `Action:*` + `Resource:*` — acceso de administrador total | CRÍTICO |
| RULE_002 | `Action:*` sobre recursos específicos | CRÍTICO |
| RULE_003 | `Resource:*` con acciones de escritura o lectura | ALTO / MEDIO |
| RULE_004 | `iam:*` — acceso total al servicio IAM | CRÍTICO |
| RULE_005 | Wildcards de servicio (`s3:*`, `ec2:*`, `kms:*`…) | ALTO |
| RULE_006 | Acciones de escalación de privilegios (`iam:AttachUserPolicy`, `sts:AssumeRole`…) | ALTO |
| RULE_007 | `NotAction` en `Effect: Allow` | ALTO |

## Arquitectura

```
EventBridge (schedule diario)
        │
        ▼
   Lambda Function
        │
        ├── AWS Organizations → lista todas las cuentas
        │
        ├── Por cada cuenta:
        │     ├── STS AssumeRole → SecurityAuditRole (cross-account)
        │     ├── Lee políticas IAM via boto3
        │     └── Aplica las 7 reglas de detección
        │
        ├── S3 → guarda reporte JSON con historial por fecha
        │
        └── SNS → email de alerta si hay hallazgos CRÍTICOS
```

Soporta **multi-cuenta** via cross-account IAM Roles y AWS Organizations. La Lambda corre en una cuenta central de seguridad y asume el `SecurityAuditRole` en cada cuenta miembro para leer sus políticas.

## Estructura del proyecto

```
iam-validator/
├── main.py                       # CLI local con soporte --aws y --file
├── lambda_function.py            # Entry point de AWS Lambda
├── analyzer/
│   ├── severity.py               # Enum de niveles de severidad
│   ├── findings.py               # Modelo de datos de un hallazgo
│   ├── rules.py                  # 7 reglas de detección
│   ├── policy_analyzer.py        # Orquestador del análisis
│   └── aws_fetcher.py            # Obtiene políticas via boto3 (single y cross-account)
├── reporter/
│   ├── report_generator.py       # Reporte en consola con colores ANSI
│   └── cloud_reporter.py         # Reporte en S3 + alertas SNS
├── deploy/
│   ├── config.env                # Configuración del deploy
│   ├── 01_setup_infra.sh         # Crea toda la infraestructura AWS (ejecutar una vez)
│   ├── 02_invoke_test.sh         # Invoca la Lambda manualmente para probar
│   ├── 03_update_code.sh         # Actualiza el código en Lambda
│   ├── 04_deploy_audit_role.sh   # Despliega SecurityAuditRole en cuentas miembro
│   └── security_audit_role.json  # CloudFormation template del rol de auditoría
└── data/
    └── sample_policies.json      # Políticas de ejemplo para pruebas locales
```

## Uso local

```bash
# Instalar dependencias
python3 -m venv .venv && source .venv/bin/activate
pip install boto3

# Analizar archivo local
python3 main.py -f data/sample_policies.json

# Analizar tu cuenta AWS real
python3 main.py --aws

# Solo hallazgos críticos y altos, exportar JSON también
python3 main.py --aws --min-severity high --output both
```

## Deploy en AWS

### Requisitos
- AWS CLI configurado (`aws configure`)
- Python 3.8+
- Permisos IAM suficientes (IAM, S3, SNS, Lambda, EventBridge)

### Setup inicial (una sola vez)

```bash
# 1. Editar configuración
nano deploy/config.env   # → cambiar ALERT_EMAIL y AWS_REGION

# 2. Crear infraestructura
bash deploy/01_setup_infra.sh

# 3. Confirmar el email que llega de AWS SNS

# 4. Probar
bash deploy/02_invoke_test.sh
```

### Deploy multi-cuenta

```bash
# Despliega SecurityAuditRole en todas las cuentas de la organización
bash deploy/04_deploy_audit_role.sh
```

Para cuentas individuales:
```bash
aws cloudformation deploy \
    --template-file deploy/security_audit_role.json \
    --stack-name iam-analyzer-security-audit-role \
    --parameter-overrides SecurityAccountId=TU_ACCOUNT_ID \
    --capabilities CAPABILITY_NAMED_IAM
```

### Actualizar código

```bash
bash deploy/03_update_code.sh
```

## Infraestructura creada en AWS

| Recurso | Nombre | Descripción |
|---|---|---|
| Lambda | `iam-policy-analyzer` | Función principal, timeout 5 min |
| S3 Bucket | `iam-analyzer-reports-{account}` | Historial de reportes JSON |
| SNS Topic | `iam-analyzer-alerts` | Canal de alertas por email |
| EventBridge | `iam-policy-analyzer-schedule` | Schedule diario 8am UTC |
| IAM Role (Lambda) | `iam-analyzer-lambda-role` | Permisos mínimos para operar |
| IAM Role (Auditoría) | `SecurityAuditRole` | Rol cross-account de solo lectura |

## Agregar una regla nueva

Abrí `analyzer/rules.py` y seguí el patrón de las reglas existentes:

```python
def check_mi_regla(statement: dict) -> List[Finding]:
    if not _is_allow(statement):
        return []
    # ... lógica de detección
    return [Finding(
        rule_id="RULE_008",
        severity=Severity.HIGH,
        title="...",
        ...
    )]

# Agregar al registro al final del archivo
ALL_RULES = [
    ...
    check_mi_regla,
]
```

## Exit codes

| Código | Significado |
|---|---|
| `0` | Sin hallazgos críticos |
| `1` | Se detectaron hallazgos CRÍTICOS — útil para bloquear pipelines CI/CD |

```bash
python3 main.py --aws || echo "Política insegura detectada — deploy bloqueado"
```

## Tecnologías

- Python 3.8+
- AWS Lambda, EventBridge, S3, SNS, IAM, STS, Organizations
- boto3, CloudFormation, StackSets
