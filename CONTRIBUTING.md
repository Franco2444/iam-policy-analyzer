# Contributing

## Correr los tests

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install boto3
python -m unittest discover -s tests -v
```

## Agregar una regla nueva

1. Abrí `analyzer/rules.py` y seguí el patrón de las reglas existentes
2. Registrá la función en `ALL_RULES` al final del archivo
3. Agregá tests en `tests/test_rules.py` cubriendo caso positivo, negativo y severidad correcta
4. Abrí un Pull Request — el CI corre automáticamente

## Pull Requests

- Un PR por feature o fix
- Los tests deben pasar antes del merge
- Describí brevemente qué detecta la regla nueva y por qué es un riesgo
