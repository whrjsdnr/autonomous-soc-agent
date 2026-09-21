"""Rebuild and package the three frozen synthetic selections; never register them."""

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from soc_agent.security_ai.packaging import load_package, save_package
from tests.packaging_support import selected_models


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    pins = {}
    with TemporaryDirectory(prefix="soc-packaging-") as directory:
        for name, (selection, rows) in selected_models(Path(directory)).items():
            path = args.output / name
            pin = save_package(selection, path)
            loaded = load_package(path, expected_manifest_digest=pin)
            # Actual post-load inference, not just serialization success.
            for row in rows:
                original = selection.selected_model.predict(row.features)
                result = loaded.predict(row.features)
                if name == "network_classifier":
                    if result != original:
                        raise ValueError("Classifier round-trip differs")
                elif (result.raw_anomaly_measure, result.anomaly_score, result.is_anomaly) != (
                    original.raw_anomaly_measure,
                    original.anomaly_score,
                    original.is_anomaly,
                ) or loaded.operating_decision(result) != selection.point.decisions(
                    (original.raw_anomaly_measure,), (original.anomaly_score,)
                )[0]:
                    raise ValueError("Anomaly round-trip differs")
            pins[name] = {
                "manifest_sha256": pin,
                "selection_digest": selection.freeze_digest,
                "roundtrip_rows": len(rows),
            }
    (args.output / "package-pins.json").write_text(json.dumps(pins, indent=2) + "\n")
    print(f"Three synthetic packages saved, loaded and verified: {args.output}")


if __name__ == "__main__":
    main()
