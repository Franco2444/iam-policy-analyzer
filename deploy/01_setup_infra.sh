#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  01_setup_infra.sh
#  Crea toda la infraestructura AWS necesaria para el IAM Policy Analyzer.
#  Corré este script UNA SOLA VEZ para preparar el ambiente.
#
#  Qué crea:
#    1. Bucket S3          → almacena los reportes JSON con historial por fecha
#    2. Topic SNS          → canal de alertas por email
#    3. Suscripción SNS    → conecta el topic a tu email (requiere confirmación)
#    4. IAM Role           → identidad que usa Lambda (sin access keys)
#    5. Políticas del Role → permisos mínimos: leer IAM + escribir S3 + publicar SNS
#    6. Función Lambda     → el script empaquetado y desplegado
#    7. EventBridge Rule   → trigger automático según el schedule configurado
#
#  Requisitos previos:
#    - AWS CLI instalado y configurado (aws configure)
#    - Python 3.8+ instalado
#    - Permisos suficientes en tu cuenta AWS (IAM, S3, SNS, Lambda, EventBridge)
# ─────────────────────────────────────────────────────────────────────────────

set -e  # detener el script si cualquier comando falla

# Cargamos la configuración
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.env"

# Evaluamos el nombre del bucket (puede contener command substitution)
S3_BUCKET_NAME=$(eval echo "$S3_BUCKET_NAME")

# Obtenemos el Account ID de la cuenta actual
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo ""
echo "════════════════════════════════════════════════════════"
echo "  IAM Policy Analyzer — Setup de Infraestructura"
echo "════════════════════════════════════════════════════════"
echo "  Cuenta AWS:  $ACCOUNT_ID"
echo "  Región:      $AWS_REGION"
echo "  Bucket S3:   $S3_BUCKET_NAME"
echo "  Email:       $ALERT_EMAIL"
echo "════════════════════════════════════════════════════════"
echo ""


# ── PASO 1: Bucket S3 ────────────────────────────────────────────────────────
echo "[1/7] Creando bucket S3: $S3_BUCKET_NAME"

if [ "$AWS_REGION" = "us-east-1" ]; then
    # us-east-1 no acepta LocationConstraint (comportamiento especial de AWS)
    aws s3api create-bucket \
        --bucket "$S3_BUCKET_NAME" \
        --region "$AWS_REGION" 2>/dev/null || echo "  (el bucket ya existe)"
else
    aws s3api create-bucket \
        --bucket "$S3_BUCKET_NAME" \
        --region "$AWS_REGION" \
        --create-bucket-configuration LocationConstraint="$AWS_REGION" 2>/dev/null || echo "  (el bucket ya existe)"
fi

# Bloqueamos acceso público al bucket (los reportes son información sensible)
aws s3api put-public-access-block \
    --bucket "$S3_BUCKET_NAME" \
    --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo "  ✓ Bucket creado y acceso público bloqueado"


# ── PASO 2: Topic SNS ────────────────────────────────────────────────────────
echo "[2/7] Creando topic SNS: $SNS_TOPIC_NAME"

SNS_TOPIC_ARN=$(aws sns create-topic \
    --name "$SNS_TOPIC_NAME" \
    --region "$AWS_REGION" \
    --query TopicArn \
    --output text)

echo "  ✓ Topic ARN: $SNS_TOPIC_ARN"


# ── PASO 3: Suscripción email ────────────────────────────────────────────────
echo "[3/7] Suscribiendo email: $ALERT_EMAIL"

aws sns subscribe \
    --topic-arn "$SNS_TOPIC_ARN" \
    --protocol email \
    --notification-endpoint "$ALERT_EMAIL" \
    --region "$AWS_REGION" > /dev/null

echo "  ✓ Suscripción creada"
echo "  ⚠  IMPORTANTE: Revisá tu email y confirmá la suscripción de AWS SNS"


# ── PASO 4: IAM Role para Lambda ─────────────────────────────────────────────
echo "[4/7] Creando IAM Role: $LAMBDA_ROLE_NAME"

# Trust policy: solo Lambda puede asumir este rol
TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "lambda.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}'

ROLE_ARN=$(aws iam create-role \
    --role-name "$LAMBDA_ROLE_NAME" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --query Role.Arn \
    --output text 2>/dev/null || \
    aws iam get-role --role-name "$LAMBDA_ROLE_NAME" --query Role.Arn --output text)

echo "  ✓ Role ARN: $ROLE_ARN"


# ── PASO 5: Políticas del IAM Role ───────────────────────────────────────────
echo "[5/7] Adjuntando políticas al Role"

# Política inline con permisos mínimos necesarios (principio de mínimo privilegio)
LAMBDA_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadIAMPolicies",
      "Effect": "Allow",
      "Action": [
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        "iam:GetPolicy",
        "iam:ListRoles",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "WriteS3Reports",
      "Effect": "Allow",
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::${S3_BUCKET_NAME}/reports/*"
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
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
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
    --policy-document "$LAMBDA_POLICY"

echo "  ✓ Políticas adjuntadas (permisos mínimos)"

# Esperamos a que el Role se propague (IAM tiene eventual consistency)
echo "  Esperando propagación del Role en AWS (10s)..."
sleep 10


# ── PASO 6: Empaquetar y crear Lambda ────────────────────────────────────────
echo "[6/7] Empaquetando y desplegando Lambda"

PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PACKAGE_DIR="$PROJECT_DIR/dist"
ZIP_FILE="$PACKAGE_DIR/lambda_package.zip"

mkdir -p "$PACKAGE_DIR"
rm -f "$ZIP_FILE"

# Copiamos solo los archivos necesarios para Lambda (sin tests, sin deploy/, etc.)
cd "$PROJECT_DIR"
zip -r "$ZIP_FILE" \
    lambda_function.py \
    analyzer/ \
    reporter/ \
    -x "**/__pycache__/*" \
    -x "**/*.pyc" \
    > /dev/null

echo "  Package creado: $ZIP_FILE"

# Creamos la función Lambda
aws lambda create-function \
    --function-name "$LAMBDA_FUNCTION_NAME" \
    --runtime python3.11 \
    --role "$ROLE_ARN" \
    --handler lambda_function.lambda_handler \
    --zip-file "fileb://$ZIP_FILE" \
    --timeout 300 \
    --memory-size 256 \
    --environment "Variables={S3_BUCKET_NAME=$S3_BUCKET_NAME,SNS_TOPIC_ARN=$SNS_TOPIC_ARN,MIN_SEVERITY=$MIN_SEVERITY}" \
    --region "$AWS_REGION" \
    --description "Analiza políticas IAM en busca de overpermissions" \
    2>/dev/null || \
aws lambda update-function-configuration \
    --function-name "$LAMBDA_FUNCTION_NAME" \
    --environment "Variables={S3_BUCKET_NAME=$S3_BUCKET_NAME,SNS_TOPIC_ARN=$SNS_TOPIC_ARN,MIN_SEVERITY=$MIN_SEVERITY}" \
    --region "$AWS_REGION" > /dev/null

echo "  ✓ Lambda desplegada"


# ── PASO 7: EventBridge Rule ─────────────────────────────────────────────────
echo "[7/7] Creando regla de schedule en EventBridge: $SCHEDULE_EXPRESSION"

RULE_ARN=$(aws events put-rule \
    --name "${LAMBDA_FUNCTION_NAME}-schedule" \
    --schedule-expression "$SCHEDULE_EXPRESSION" \
    --state ENABLED \
    --description "Dispara el IAM Policy Analyzer según el schedule configurado" \
    --region "$AWS_REGION" \
    --query RuleArn \
    --output text)

# Damos permiso a EventBridge para invocar la Lambda
aws lambda add-permission \
    --function-name "$LAMBDA_FUNCTION_NAME" \
    --statement-id "EventBridgeInvoke" \
    --action lambda:InvokeFunction \
    --principal events.amazonaws.com \
    --source-arn "$RULE_ARN" \
    --region "$AWS_REGION" 2>/dev/null || true

# Conectamos la regla con la Lambda
LAMBDA_ARN="arn:aws:lambda:${AWS_REGION}:${ACCOUNT_ID}:function:${LAMBDA_FUNCTION_NAME}"
aws events put-targets \
    --rule "${LAMBDA_FUNCTION_NAME}-schedule" \
    --targets "Id=1,Arn=$LAMBDA_ARN" \
    --region "$AWS_REGION" > /dev/null

echo "  ✓ EventBridge configurado ($SCHEDULE_EXPRESSION)"


# ── Resumen final ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✓ Infraestructura creada exitosamente"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  S3 Bucket:      s3://$S3_BUCKET_NAME"
echo "  SNS Topic:      $SNS_TOPIC_ARN"
echo "  Lambda:         $LAMBDA_ARN"
echo "  Schedule:       $SCHEDULE_EXPRESSION"
echo ""
echo "  Próximos pasos:"
echo "  1. Confirmá la suscripción en tu email ($ALERT_EMAIL)"
echo "  2. Para probar manualmente:"
echo "     bash deploy/02_invoke_test.sh"
echo ""
