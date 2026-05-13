# IAM Policy Analyzer

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![AWS Lambda](https://img.shields.io/badge/AWS-Lambda-orange?logo=awslambda&logoColor=white)
![CI/CD](https://github.com/Franco2444/iam-policy-analyzer/actions/workflows/test.yml/badge.svg)

Herramienta de seguridad para AWS que analiza políticas IAM en busca de overpermissions, wildcards peligrosos y acciones de escalación de privilegios. Corre automáticamente todos los días como Lambda serverless, soporta múltiples cuentas via AWS Organizations y envía alertas por email cuando detecta hallazgos críticos.

## ¿Qué detecta?

| Regla | Descripción | Severidad |
|---|---|---|
| RULE_001 | `Action:*` + `Resource:*` — acceso de administrador total | 🔴 CRÍTICO |
| RULE_002 | `Action:*` sobre recursos específicos | 🔴 CRÍTICO |
| RULE_003 | `Resource:*` con acciones de escritura o lectura | 🟠 ALTO / 🟡 MEDIO |
| RULE_004 | `iam:*` — acceso total al servicio IAM | 🔴 CRÍTICO |
| RULE_005 | Wildcards de servicio (`s3:*`, `ec2:*`, `kms:*`…) | 🟠 ALTO |
| RULE_006 | Acciones de escalación de privilegios (`iam:AttachUserPolicy`, `sts:AssumeRole`…) | 🟠 ALTO |
| RULE_007 | `NotAction` en `Effect: Allow` | 🟠 ALTO |

## Ejemplo de salida

```
════════════════════════════════════════════════════════════════════════
   IAM POLICY ANALYZER  ·  Reporte de Seguridad AWS
════════════════════════════════════════════════════════════════════════
   Fecha:    2026-05-12  19:01:16
   Política: cuenta-aws-real

  RESUMEN  (23 hallazgos)
  ────────────────────────────────────────
  🔴 CRÍTICO      2   ██
  🟠 ALTO         8   ████████
  🟡 MEDIO       13   █████████████
  ────────────────────────────────────────

  [01] 🔴 CRÍTICO  Acceso de administrador total (Action:* + Resource:*)
       Regla: RULE_001  |  Política: AdministradorTotal  |  SID: FullAdminAccess

       ¿Por qué es un riesgo?
       El statement otorga permisos de administrador completo sobre absolutamente
       todos los servicios y recursos de la cuenta AWS. Cualquier usuario o rol
       con esta política puede crear, modificar, eliminar y acceder a cualquier
       recurso, incluyendo credenciales, datos y configuración de red.

       Acciones afectadas:  *
       Recursos afectados:  *

       Remediación:
       Define las acciones específicas que el rol/usuario necesita. Usa el
       servicio IAM Access Analyzer → 'Generate policy' para obtener una política
       mínima basada en el uso real de los últimos 90 días.

  ──────────────────────────────────────────────────────────────────────
  [02] 🟠 ALTO  Wildcard de servicio sensible: s3:*
       Regla: RULE_005  |  Política: DesarrolladorSobrePermisado

       ¿Por qué es un riesgo?
       's3:*' otorga acceso total al servicio S3. Permite acceso completo
       a todos los buckets S3 de la cuenta.

       Acciones afectadas:  s3:*
       Recursos afectados:  *

       Remediación:
       Reemplaza 's3:*' con las acciones específicas necesarias:
       ['s3:GetObject', 's3:PutObject', 's3:ListBucket']

  ──────────────────────────────────────────────────────────────────────

  ⚠  2 hallazgo(s) CRÍTICO(s) requieren acción inmediata.
  ▲  8 hallazgo(s) de severidad ALTA.
════════════════════════════════════════════════════════════════════════
```

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
        ├── S3 → guarda reporte JSON con historial por fecha/cuenta
        │
        └── SNS → email de alerta si hay hallazgos CRÍTICOS o ALTOS
```

Soporta **multi-cuenta** via cross-account IAM Roles y AWS Organizations. La Lambda corre en una cuenta central de seguridad y asume el `SecurityAuditRole` en cada cuenta miembro para leer sus políticas IAM.

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
├── tests/
│   └── test_rules.py             # 20 tests unitarios con unittest
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

# Correr los tests
python -m unittest discover -s tests -v
```

## Deploy en AWS

### Requisitos
- AWS CLI configurado (`aws configure`)
- Python 3.8+
- Permisos IAM: IAM, S3, SNS, Lambda, EventBridge

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
| Lambda | `iam-policy-analyzer` | Función principal, timeout 5 min, 256MB |
| S3 Bucket | `iam-analyzer-reports-{account}` | Historial de reportes JSON cifrados |
| SNS Topic | `iam-analyzer-alerts` | Alertas por email (CRÍTICO y ALTO) |
| EventBridge | `iam-policy-analyzer-schedule` | Schedule diario 8am UTC |
| IAM Role (Lambda) | `iam-analyzer-lambda-role` | Permisos mínimos para operar |
| IAM Role (Auditoría) | `SecurityAuditRole` | Rol cross-account de solo lectura |

## Agregar una regla nueva

Abrí `analyzer/rules.py` y seguí el patrón:

```python
def check_mi_regla(statement: dict) -> List[Finding]:
    if not _is_allow(statement):
        return []
    # lógica de detección...
    return [Finding(
        rule_id="RULE_008",
        severity=Severity.HIGH,
        title="Descripción corta",
        description="Explicación del riesgo",
        statement_sid=_sid(statement),
        affected_actions=[...],
        affected_resources=[...],
        remediation="Cómo corregirlo",
    )]

# Registrar al final del archivo
ALL_RULES = [..., check_mi_regla]
```

## Exit codes

| Código | Significado |
|---|---|
| `0` | Sin hallazgos críticos |
| `1` | Se detectaron hallazgos CRÍTICOS |

```bash
# Bloquear deploy en CI/CD si hay políticas inseguras
python3 main.py --aws || echo "Deploy bloqueado — políticas inseguras detectadas"
```

## Costos estimados

Asumiendo **50 cuentas AWS** con ejecución **diaria** (30 días/mes):

| Servicio | Uso mensual | Costo estimado |
|---|---|---|
| **Lambda** | 1.500 invocaciones × ~4s × 256MB = 6.000 GB-s | ~$0.09 |
| **S3** | 1.500 archivos JSON (~100KB c/u) + PUT requests | ~$0.01 |
| **SNS** | Variable según alertas (email: $2 / 100k notif.) | ~$0.00 |
| **EventBridge** | 1.500 eventos ($1 / 1M eventos) | ~$0.00 |
| **Total** | | **~$0.10 / mes** |

> El tier gratuito de AWS cubre la mayoría del uso: 1M invocaciones Lambda, 400.000 GB-s de cómputo, 5GB S3, y 1.000 notificaciones SNS email por mes.

## Tecnologías

- Python 3.8+
- AWS Lambda, EventBridge, S3, SNS, IAM, STS, Organizations
- boto3, CloudFormation, StackSets
- GitHub Actions (CI/CD)
