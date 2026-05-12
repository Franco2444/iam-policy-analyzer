#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  04_deploy_audit_role.sh
#  Despliega el SecurityAuditRole en TODAS las cuentas de la organización.
#
#  Usa CloudFormation StackSets — el mecanismo de AWS para desplegar la misma
#  stack en múltiples cuentas/regiones con un solo comando.
#
#  Qué hace:
#    1. Crea un StackSet en la cuenta de seguridad (management o delegada)
#    2. Despliega el SecurityAuditRole en todas las cuentas de la org
#    3. Cada cuenta queda lista para ser escaneada por la Lambda
#
#  Requisito: tu cuenta debe ser la management account de la organización
#  o tener delegación de administración para CloudFormation StackSets.
#
#  Si preferís hacerlo manualmente en una sola cuenta:
#    aws cloudformation deploy \
#      --template-file deploy/security_audit_role.json \
#      --stack-name security-audit-role \
#      --parameter-overrides SecurityAccountId=TU_ACCOUNT_ID \
#      --capabilities CAPABILITY_NAMED_IAM \
#      --region us-east-1
# ─────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.env"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
STACKSET_NAME="iam-analyzer-security-audit-role"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Desplegando SecurityAuditRole en la organización"
echo "════════════════════════════════════════════════════════"
echo "  Cuenta de seguridad:  $ACCOUNT_ID"
echo "  Región:               $AWS_REGION"
echo "  StackSet:             $STACKSET_NAME"
echo "════════════════════════════════════════════════════════"
echo ""


# ── PASO 1: Habilitar confianza entre Organizations y CloudFormation ──────────
echo "[1/3] Habilitando trusted access para CloudFormation StackSets..."

aws organizations enable-aws-service-access \
    --service-principal stacksets.cloudformation.amazonaws.com 2>/dev/null || true

echo "  ✓ Trusted access habilitado"


# ── PASO 2: Crear el StackSet ─────────────────────────────────────────────────
echo "[2/3] Creando StackSet: $STACKSET_NAME"

TEMPLATE_BODY=$(cat "$SCRIPT_DIR/security_audit_role.json")

aws cloudformation create-stack-set \
    --stack-set-name "$STACKSET_NAME" \
    --template-body "$TEMPLATE_BODY" \
    --parameters \
        "ParameterKey=SecurityAccountId,ParameterValue=$ACCOUNT_ID" \
        "ParameterKey=LambdaRoleName,ParameterValue=$LAMBDA_ROLE_NAME" \
    --capabilities CAPABILITY_NAMED_IAM \
    --permission-model SERVICE_MANAGED \
    --auto-deployment "Enabled=true,RetainStacksOnAccountRemoval=false" \
    --region "$AWS_REGION" 2>/dev/null || \
aws cloudformation update-stack-set \
    --stack-set-name "$STACKSET_NAME" \
    --template-body "$TEMPLATE_BODY" \
    --parameters \
        "ParameterKey=SecurityAccountId,ParameterValue=$ACCOUNT_ID" \
        "ParameterKey=LambdaRoleName,ParameterValue=$LAMBDA_ROLE_NAME" \
    --capabilities CAPABILITY_NAMED_IAM \
    --region "$AWS_REGION" > /dev/null

echo "  ✓ StackSet creado/actualizado"


# ── PASO 3: Desplegar en todas las cuentas de la org ─────────────────────────
echo "[3/3] Desplegando en todas las cuentas de la organización..."

ROOT_ID=$(aws organizations list-roots --query 'Roots[0].Id' --output text)

aws cloudformation create-stack-instances \
    --stack-set-name "$STACKSET_NAME" \
    --deployment-targets "OrganizationalUnitIds=$ROOT_ID" \
    --regions "$AWS_REGION" \
    --operation-preferences \
        "FailureTolerancePercentage=20,MaxConcurrentPercentage=25" \
    --region "$AWS_REGION" 2>/dev/null || echo "  (instancias ya existentes, actualizando...)"

echo "  ✓ Despliegue iniciado en todas las cuentas"
echo ""
echo "  El despliegue es asíncrono. Para ver el progreso:"
echo "  aws cloudformation describe-stack-set-operation \\"
echo "      --stack-set-name $STACKSET_NAME \\"
echo "      --operation-id \$(aws cloudformation list-stack-set-operations \\"
echo "          --stack-set-name $STACKSET_NAME \\"
echo "          --query 'Summaries[0].OperationId' --output text)"
echo ""


# ── PASO 4: Actualizar Lambda con AUDIT_ROLE_NAME ────────────────────────────
echo "Activando modo multi-cuenta en la Lambda..."

aws lambda update-function-configuration \
    --function-name "$LAMBDA_FUNCTION_NAME" \
    --environment "Variables={
        S3_BUCKET_NAME=$(eval echo $S3_BUCKET_NAME),
        SNS_TOPIC_ARN=$(aws sns list-topics --query "Topics[?contains(TopicArn,'$SNS_TOPIC_NAME')].TopicArn" --output text),
        MIN_SEVERITY=$MIN_SEVERITY,
        AUDIT_ROLE_NAME=SecurityAuditRole
    }" \
    --region "$AWS_REGION" > /dev/null

echo "  ✓ Lambda actualizada con AUDIT_ROLE_NAME=SecurityAuditRole"


# ── PASO 5: Actualizar permisos del rol de Lambda ────────────────────────────
echo "Actualizando permisos del IAM Role de Lambda..."

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
SNS_TOPIC_ARN=$(aws sns list-topics \
    --query "Topics[?contains(TopicArn,'$SNS_TOPIC_NAME')].TopicArn" \
    --output text)
S3_BUCKET=$(eval echo "$S3_BUCKET_NAME")

UPDATED_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadIAMPolicies",
      "Effect": "Allow",
      "Action": [
        "iam:ListPolicies", "iam:GetPolicyVersion", "iam:GetPolicy",
        "iam:ListRoles", "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ListOrganizationAccounts",
      "Effect": "Allow",
      "Action": ["organizations:ListAccounts", "organizations:DescribeAccount"],
      "Resource": "*"
    },
    {
      "Sid": "AssumeAuditRoleInMemberAccounts",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/SecurityAuditRole"
    },
    {
      "Sid": "WriteS3Reports",
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::${S3_BUCKET}/reports/*"
    },
    {
      "Sid": "PublishSNSAlerts",
      "Effect": "Allow",
      "Action": ["sns:Publish"],
      "Resource": "${SNS_TOPIC_ARN}"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:${AWS_REGION}:${ACCOUNT_ID}:log-group:/aws/lambda/${LAMBDA_FUNCTION_NAME}:*"
    }
  ]
}
EOF
)

aws iam put-role-policy \
    --role-name "$LAMBDA_ROLE_NAME" \
    --policy-name "${LAMBDA_FUNCTION_NAME}-policy" \
    --policy-document "$UPDATED_POLICY"

echo "  ✓ Permisos actualizados (organizations + sts:AssumeRole)"


# ── PASO 6: Subir código actualizado a Lambda ─────────────────────────────────
echo "Subiendo código actualizado a Lambda..."
bash "$SCRIPT_DIR/03_update_code.sh"


echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✓ Multi-cuenta configurado"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  Próximo paso: esperar que el StackSet termine de desplegarse"
echo "  (~5-10 min según cantidad de cuentas) y luego probar:"
echo ""
echo "  bash deploy/02_invoke_test.sh"
echo ""
