"""Opt-in offline reference softmax; does not change native classifier inference."""

from decimal import ROUND_HALF_EVEN, Context, Decimal, localcontext

import numpy as np

REFERENCE_SOFTMAX = "decimal-softmax-binary64:v1"


def reference_softmax(margins: np.ndarray) -> np.ndarray:
    """Evaluate mathematical softmax using explicit decimal arithmetic, not expf.

    Input margins must already be identical. No metric rounding or hash changes.
    Precision is part of the new evaluation contract, not a native prediction alias.
    """
    values = np.asarray(margins)
    if values.ndim != 2 or not values.size or values.shape[1] < 2 or not np.isfinite(values).all():
        raise ValueError("Finite nonempty aligned margins required")
    if values.dtype not in (np.dtype("float32"), np.dtype("float64")):
        raise ValueError("Floating point margins required")
    result = []
    for row in values:
        exact = [Decimal.from_float(float(v)) for v in row]
        maximum = max(exact)
        rounded = []
        for precision in (80, 120):
            with localcontext(Context(prec=precision, rounding=ROUND_HALF_EVEN)):
                weights = [(value - maximum).exp() for value in exact]
                total = sum(weights, Decimal(0))
                rounded.append([float(weight / total) for weight in weights])
        if rounded[0] != rounded[1]:
            raise ValueError("Reference probability precision unstable")
        result.append(rounded[0])
    output = np.asarray(result, dtype=np.float64)
    if not np.isfinite(output).all() or not np.allclose(output.sum(axis=1), 1, rtol=0, atol=2**-50):
        raise ValueError("Invalid reference probability normalization")
    return output
