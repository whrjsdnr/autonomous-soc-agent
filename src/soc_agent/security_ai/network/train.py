"""Explicit local inspection/training CLI. No downloads or import-time work."""

import argparse
from datetime import datetime
from pathlib import Path

from soc_agent.security_ai.network.dataset import CICIDS2017Adapter


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--dataset-name", default="CIC-IDS2017")
    parser.add_argument("--dataset-version", default="1")
    parser.add_argument("--model-version", default="1.0.0")
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument(
        "--observed-at", help="Required timezone-aware dataset observation reference"
    )
    parser.add_argument("--invalid-policy", choices=("reject", "drop"), default="reject")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-estimators", type=int, default=40)
    args = parser.parse_args()
    paths = tuple(args.data_dir.glob("*.csv"))
    adapter = CICIDS2017Adapter(
        dataset_name=args.dataset_name, dataset_version=args.dataset_version
    )
    try:
        inspection = adapter.inspect(paths)
        print(inspection.model_dump_json(indent=2))
        if args.inspect_only:
            return
        if args.observed_at is None:
            parser.error("--observed-at is required for training (not inferred from filenames)")
        from soc_agent.security_ai.network.artifacts import save_artifact
        from soc_agent.security_ai.network.training import TrainingConfig, train

        dataset = adapter.load(
            paths,
            observed_at=datetime.fromisoformat(args.observed_at),
            invalid_policy=args.invalid_policy,
        )
        result = train(
            dataset,
            config=TrainingConfig(seed=args.seed, n_estimators=args.n_estimators),
            model_version=args.model_version,
        )
        destination = save_artifact(result, args.output_dir)
        print(result.metadata.model_dump_json(indent=2))
        print(f"Artifact: {destination}")
    except (ValueError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
