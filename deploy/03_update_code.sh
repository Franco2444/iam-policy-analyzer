#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  03_update_code.sh
#  Actualiza el código de la Lambda sin tocar la infraestructura.
#  Corré este script cada vez que modificás las reglas u otro archivo Python.
# ─────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.env"

PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ZIP_FILE="$PROJECT_DIR/dist/lambda_package.zip"

echo "Empaquetando código actualizado..."

cd "$PROJECT_DIR"
rm -f "$ZIP_FILE"
zip -r "$ZIP_FILE" \
    lambda_function.py \
    analyzer/ \
    reporter/ \
    -x "**/__pycache__/*" \
    -x "**/*.pyc" \
    > /dev/null

echo "Actualizando Lambda: $LAMBDA_FUNCTION_NAME"

aws lambda update-function-code \
    --function-name "$LAMBDA_FUNCTION_NAME" \
    --zip-file "fileb://$ZIP_FILE" \
    --region "$AWS_REGION" \
    --query '[FunctionName, CodeSize, LastModified]' \
    --output table

echo ""
echo "✓ Lambda actualizada. Podés probarla con: bash deploy/02_invoke_test.sh"
