import argparse
import json
from pathlib import Path

import joblib
import csv
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline


def canonical_label(label: str) -> str:
    normalized = label.lower().replace("_", " ")
    if "safe" in normalized:
        return "safe"
    if "reentrancy" in normalized:
        return "Reentrancy"
    if "access control" in normalized:
        return "Access Control"
    if "overflow" in normalized or "underflow" in normalized or "integer" in normalized:
        return "Arithmetic Overflow/Underflow"
    if "timestamp" in normalized or "block number" in normalized:
        return "Timestamp Dependence"
    if "unchecked external" in normalized:
        return "Unchecked External Call"
    return "Other"


def load_jsonl_examples(dataset_path: Path) -> tuple[list[str], list[str], list[str]]:
    texts: list[str] = []
    labels: list[str] = []
    groups: list[str] = []
    with dataset_path.open(encoding="utf-8") as dataset_file:
        for raw_line in dataset_file:
            record = json.loads(raw_line)
            vulnerable_code = record.get("vulnerable_code", "").strip()
            fixed_code = record.get("fixed_code", "").strip()
            vulnerability_type = record.get("vulnerability_type", "Other")
            if vulnerable_code:
                texts.append(vulnerable_code)
                labels.append(canonical_label(vulnerability_type))
                groups.append(f"jsonl:{record.get('id', len(groups))}")
            if fixed_code:
                texts.append(fixed_code)
                labels.append("safe")
                groups.append(f"jsonl:{record.get('id', len(groups))}")
    return texts, labels, groups


def load_csv_examples(dataset_path: Path) -> tuple[list[str], list[str], list[str]]:
    texts: list[str] = []
    labels: list[str] = []
    groups: list[str] = []
    with dataset_path.open(encoding="utf-8", errors="replace", newline="") as dataset_file:
        for record in csv.DictReader(dataset_file):
            code = record.get("code", "").strip()
            if not code:
                continue
            texts.append(code)
            labels.append(canonical_label(record.get("label", "Other")))
            groups.append(f"csv:{record.get('filename', len(groups))}")
    return texts, labels, groups


def load_examples(dataset_paths: list[Path]) -> tuple[list[str], list[str], list[str]]:
    examples = [
        load_jsonl_examples(path) if path.suffix.lower() == ".jsonl" else load_csv_examples(path)
        for path in dataset_paths
    ]
    texts = [text for batch in examples for text in batch[0]]
    labels = [label for batch in examples for label in batch[1]]
    groups = [group for batch in examples for group in batch[2]]
    return texts, labels, groups


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the SecureXAI Solidity ML classifier.")
    parser.add_argument(
        "datasets",
        type=Path,
        nargs="+",
        help="Paths to the Kaggle JSONL and/or CSV datasets.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/securexai_ml.joblib"),
        help="Output model artifact path.",
    )
    args = parser.parse_args()

    texts, labels, groups = load_examples(args.datasets)
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_indices, test_indices = next(splitter.split(texts, labels, groups))
    train_texts = [texts[index] for index in train_indices]
    test_texts = [texts[index] for index in test_indices]
    train_labels = [labels[index] for index in train_indices]
    test_labels = [labels[index] for index in test_indices]
    model = Pipeline(
        [
            ("features", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=120_000)),
            ("classifier", LogisticRegression(max_iter=1_000, class_weight="balanced")),
        ]
    )
    model.fit(train_texts, train_labels)
    predictions = model.predict(test_texts)
    print(classification_report(test_labels, predictions, zero_division=0))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "labels": list(model.classes_),
            "datasets": [str(dataset) for dataset in args.datasets],
            "random_state": 42,
            "split": "grouped-80-20",
        },
        args.output,
    )
    print(f"Saved model to {args.output.resolve()}")


if __name__ == "__main__":
    main()