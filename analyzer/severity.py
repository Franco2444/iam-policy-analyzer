"""
Define los niveles de severidad usados en todos los hallazgos del analizador.

Cada nivel tiene tres atributos:
  score  → número entero para comparar y ordenar severidades
  label  → texto en español para los reportes
  color  → código ANSI para la terminal
"""

from enum import Enum


class Severity(Enum):
    # El valor del Enum es una tupla (score, label, color_ansi)
    CRITICAL = (4, "CRÍTICO", "\033[91m")   # rojo brillante
    HIGH     = (3, "ALTO",    "\033[31m")   # rojo
    MEDIUM   = (2, "MEDIO",   "\033[33m")   # amarillo
    LOW      = (1, "BAJO",    "\033[34m")   # azul

    # Python llama a __init__ con los elementos de la tupla
    def __init__(self, score: int, label: str, color: str):
        self.score = score
        self.label = label
        self.color = color

    @classmethod
    def from_string(cls, s: str) -> "Severity":
        """Convierte un string (ej: 'high', 'alto') al Enum correspondiente."""
        mapping = {
            "critical": cls.CRITICAL, "critico": cls.CRITICAL,
            "high":     cls.HIGH,     "alto":    cls.HIGH,
            "medium":   cls.MEDIUM,   "medio":   cls.MEDIUM,
            "low":      cls.LOW,      "bajo":    cls.LOW,
        }
        result = mapping.get(s.lower())
        if result is None:
            raise ValueError(f"Severidad desconocida: '{s}'. Opciones: {list(mapping.keys())}")
        return result
