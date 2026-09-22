"""All-or-nothing fusion failures; no partial result is returned."""


class FusionValidationError(ValueError):
    """Invalid signal, contract, provenance, or incident binding."""


class FusionIdentityCollision(FusionValidationError):
    """One stable identity was presented with different contents."""
