# Changelog

## [1.0.0] - 2025-05-12

### Features
- **7 reglas de detección IAM** con severidad CRÍTICO / ALTO / MEDIO / BAJO
  - RULE_001: `Action:*` + `Resource:*` — acceso de administrador total
  - RULE_002: `Action:*` sobre recursos específicos
  - RULE_003: `Resource:*` con acciones de escritura o lectura
  - RULE_004: `iam:*` — control total sobre identidades y accesos
  - RULE_005: Wildcards de servicio sensibles (`s3:*`, `ec2:*`, `kms:*`…)
  - RULE_006: Acciones de escalación de privilegios (`iam:AttachUserPolicy`, `sts:AssumeRole`…)
  - RULE_007: `NotAction` en `Effect: Allow`

- **CLI local** (`main.py`) con flags `--file` y `--aws`
  - Análisis de archivos JSON locales
  - Conexión directa a cuenta AWS real via boto3
  - Salida en consola con colores ANSI, JSON, o ambos
  - Filtro por severidad mínima (`--min-severity`)
  - Exit code 1 cuando hay hallazgos CRÍTICOS (integración CI/CD)

- **Arquitectura serverless en AWS**
  - Lambda Function con timeout de 5 minutos y 256MB de memoria
  - EventBridge schedule diario configurable (default: 8am UTC)
  - S3 bucket con historial de reportes JSON organizados por fecha
  - SNS topic con alertas por email para hallazgos CRÍTICOS y ALTOS

- **Soporte multi-cuenta** via AWS Organizations
  - Cross-account IAM Roles con STS AssumeRole
  - `SecurityAuditRole` con permisos mínimos de solo lectura
  - CloudFormation template para deploy del rol en cuentas miembro
  - Scripts de deploy con CloudFormation StackSets

- **Scripts de infraestructura** (`deploy/`)
  - `01_setup_infra.sh` — crea toda la infraestructura desde cero
  - `02_invoke_test.sh` — invoca la Lambda manualmente
  - `03_update_code.sh` — actualiza el código sin tocar la infra
  - `04_deploy_audit_role.sh` — despliega SecurityAuditRole en la organización

- **Tests unitarios** (`tests/test_rules.py`)
  - 20 tests cubriendo las 3 reglas principales
  - Casos positivos, negativos y edge cases

- **CI/CD** con GitHub Actions
  - Ejecuta tests unitarios en cada push y pull request
  - Corre el analyzer sobre políticas de ejemplo
  - Falla si detecta hallazgos críticos
