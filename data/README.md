# Local datasets

Place manually obtained CIC-IDS2017 CSV files in `data/raw/cicids2017/`.
Raw/processed data and `artifacts/` are ignored by Git. Nothing is downloaded.

No actual CIC-IDS2017 data was supplied for Phase 3-2. Tests generate explicitly
synthetic CIC-like CSVs in temporary directories; their metrics are not real IDS
performance. See `docs/network-attack-classifier.md` for the supported column
contract, grouping requirements and commands. Do not rename synthetic fixtures as
actual CIC-IDS2017 results.
