#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  02_invoke_test.sh
#  Invoca la Lambda manualmente para probar que todo funciona.
#  No espera al schedule de EventBridge — lo dispara ahora mismo.
#
#  Mostrará en consola:
#    - El output de la Lambda (resumen de hallazgos)
#    - El log de CloudWatch (para debug si algo falla)
# ─────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.env"

echo ""
echo "Invocando Lambda: $LAMBDA_FUNCTION_NAME"
echo ""

OUTPUT_FILE="/tmp/lambda_output.json"

aws lambda invoke \
    --function-name "$LAMBDA_FUNCTION_NAME" \
    --region "$AWS_REGION" \
    --log-type Tail \
    --payload '{}' \
    --query 'LogResult' \
    --output text \
    "$OUTPUT_FILE" | base64 --decode

echo ""
echo "────────────────────────────────────────"
echo "Respuesta de la función:"
cat "$OUTPUT_FILE" | python3 -m json.tool
echo ""
