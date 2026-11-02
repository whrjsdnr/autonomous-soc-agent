# Read-only notebook source extracts

학습을 재실행하지 않은 원본 Cell 발췌. SHA는 Evidence_Manifest에 기록. 저장된 실행 상태와 코드의 현재 상태는 다를 수 있다.

## dnn_top40_v4.ipynb cell 3

```python
class NetworkThreatDNN(nn.Module):
    def __init__(
        self,
        input_dim=40,
        num_classes=15,
    ):
        super().__init__()

        self.network = nn.Sequential(
            nn.Linear(
                input_dim,
                128,
            ),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.20),
            nn.Linear(
                128,
                128,
            ),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.20),
            nn.Linear(
                128,
                64,
            ),
            nn.ReLU(),
            nn.Linear(
                64,
                num_classes,
            ),
        )

    def forward(
        self,
        x,
    ):
        return self.network(x)
```

## dnn_top40_v4.ipynb cell 8

```python
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

print("Device:", device)


model = NetworkThreatDNN().to(device)


optimizer = torch.optim.AdamW(
    model.parameters(),
    lr=1e-3,
    weight_decay=1e-4,
)


criterion = nn.CrossEntropyLoss(reduction="none")
```

## dnn_top40_v4.ipynb cell 16

```python
MAX_EPOCHS = 15
PATIENCE = 3

BEST_MODEL_PATH = MODEL_DIR / "dnn_top40_v4_best.pt"

HISTORY_PATH = RESULT_DIR / "training_history.csv"


best_macro_f1 = epoch1_metrics["macro_f1"]

best_epoch = 1

patience_count = 0


history = [
    {
        "epoch": 1,
        "train_loss": loss,
        **epoch1_metrics,
    }
]


# epoch 1을 현재 best로 저장
torch.save(
    {
        "epoch": 1,
        "model_state_dict": model.state_dict(),
        "optimizer_state_dict": optimizer.state_dict(),
        "top40_features": TOP40_FEATURES,
        "scaler_path": str(SCALER_PATH),
        "metrics": epoch1_metrics,
    },
    BEST_MODEL_PATH,
)


for epoch in range(
    2,
    MAX_EPOCHS + 1,
):
    print()
    print(f"========== EPOCH {epoch} ==========")

    train_loss, train_time = train_one_epoch(
        model,
        train_loader,
        optimizer,
        criterion,
        device,
    )

    metrics = evaluate_dnn(
        model,
        valid_loader,
        device,
    )

    history.append(
        {
            "epoch": epoch,
            "train_loss": train_loss,
            "train_seconds": train_time,
            **metrics,
        }
    )

    print(f"Train loss      : {train_loss:.6f}")

    print(f"Accuracy        : {metrics['accuracy']:.6f}")

    print(f"Macro Precision : {metrics['macro_precision']:.6f}")

    print(f"Macro Recall    : {metrics['macro_recall']:.6f}")

    print(f"Macro F1        : {metrics['macro_f1']:.6f}")

    print(f"Weighted F1     : {metrics['weighted_f1']:.6f}")

    # ----------------------------------------
    # best checkpoint
    # ----------------------------------------

    if metrics["macro_f1"] > best_macro_f1:
        best_macro_f1 = metrics["macro_f1"]

        best_epoch = epoch

        patience_count = 0

        torch.save(
            {
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "top40_features": TOP40_FEATURES,
                "scaler_path": str(SCALER_PATH),
                "metrics": metrics,
            },
            BEST_MODEL_PATH,
        )

        print(f"[BEST] epoch={epoch} macro_f1={best_macro_f1:.6f}")

    else:
        patience_count += 1

        print(f"[NO IMPROVEMENT] {patience_count}/{PATIENCE}")

    # 매 epoch history 저장
    pd.DataFrame(history).to_csv(
        HISTORY_PATH,
        index=False,
    )

    if patience_count >= PATIENCE:
        print()
        print("[EARLY STOPPING]")

        break
```

## dnn_top40_v4.ipynb cell 39

```python
import torch
import torch.nn as nn


class NetworkThreatDNN(nn.Module):
    def __init__(
        self,
        input_dim=40,
        num_classes=15,
    ):
        super().__init__()

        self.network = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.20),
            nn.Linear(128, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.20),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, num_classes),
        )

    def forward(self, x):
        return self.network(x)


print("NetworkThreatDNN defined")
```

## model_diversity_v3.ipynb cell 15

```python
MLP_MODEL_PATH = MODEL_DIR / "mlp_top40_v3.joblib"

MLP_RESULT_DIR = PROJECT_ROOT / "results/mlp_top40_v3"

mlp_model = MLPClassifier(
    hidden_layer_sizes=(64, 32),
    activation="relu",
    solver="adam",
    batch_size=2048,
    learning_rate="adaptive",
    learning_rate_init=0.001,
    max_iter=100,
    early_stopping=True,
    validation_fraction=0.1,
    n_iter_no_change=8,
    random_state=42,
    verbose=True,
)

print("Training MLP...")

start = time.perf_counter()

mlp_model.fit(
    X_train,
    y_train,
)

train_time = time.perf_counter() - start

print(f"\nTraining time: {train_time / 60:.2f} min")
print("Iterations   :", mlp_model.n_iter_)
```

## model_sample_v4.ipynb cell 60

```python
import numpy as np
import pandas as pd
import lightgbm as lgb
import gc
import time

from pathlib import Path
from sklearn.metrics import confusion_matrix


# ============================================================
# 1. 저장된 V4-A 모델 다시 로드
# ============================================================

model_v4a = lgb.Booster(model_file=str(V4A_MODEL_PATH))

print("Loaded model:", V4A_MODEL_PATH)

print("Features:", model_v4a.num_feature())

assert model_v4a.num_feature() == 40


# ============================================================
# 2. 결과 디렉터리
# ============================================================

V4A_RESULT_DIR = PROJECT_ROOT / "results" / "lightgbm_top40_v4a"

V4A_RESULT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# 3. Streaming evaluation
# ============================================================

N_CLASSES = 15
BATCH_SIZE = 100_000

cm_v4a = np.zeros(
    (N_CLASSES, N_CLASSES),
    dtype=np.int64,
)

total_rows = 0
correct_rows = 0


valid_select_sql = ", ".join(
    [quote_identifier(feature) for feature in TOP40_FEATURES] + ["label_id"]
)


reader = con.execute(
    f"""
    SELECT
        {valid_select_sql}

    FROM read_parquet(
        '{VALID_TOP40_PATH}'
    )
    """
).fetch_record_batch(rows_per_batch=BATCH_SIZE)


start = time.perf_counter()


for batch_id, batch in enumerate(
    reader,
    start=1,
):
    batch_df = batch.to_pandas()

    X_batch = batch_df[TOP40_FEATURES].to_numpy(
        dtype=np.float32,
        copy=False,
    )

    y_batch = batch_df["label_id"].to_numpy(
        dtype=np.int16,
        copy=False,
    )

    proba = model_v4a.predict(
        X_batch,
        num_threads=2,
    )

    pred = np.argmax(
        proba,
        axis=1,
    ).astype(np.int16)

    cm_v4a += confusion_matrix(
        y_batch,
        pred,
        labels=np.arange(N_CLASSES),
    )

    total_rows += len(y_batch)

    correct_rows += int(np.sum(pred == y_batch))

    if batch_id == 1 or batch_id % 5 == 0:
        print(
            f"[batch {batch_id:02d}] rows={total_rows:,} accuracy={correct_rows / total_rows:.6f}"
        )

    del (
        batch_df,
        X_batch,
        y_batch,
        proba,
        pred,
    )

    gc.collect()


eval_elapsed = time.perf_counter() - start


print("\nValidation rows:", f"{total_rows:,}")

print("Evaluation time:", f"{eval_elapsed:.1f}s")


assert total_rows == 2_390_002


# ============================================================
# 4. Metrics from confusion matrix
# ============================================================

tp = np.diag(cm_v4a).astype(np.float64)

support = cm_v4a.sum(axis=1).astype(np.float64)

predicted = cm_v4a.sum(axis=0).astype(np.float64)


precision = np.divide(
    tp,
    predicted,
    out=np.zeros_like(tp),
    where=predicted != 0,
)


recall = np.divide(
    tp,
    support,
    out=np.zeros_like(tp),
    where=support != 0,
)


f1 = np.divide(
    2 * precision * recall,
    precision + recall,
    out=np.zeros_like(tp),
    where=(precision + recall) != 0,
)


accuracy = tp.sum() / support.sum()

macro_precision = precision.mean()

macro_recall = recall.mean()

macro_f1 = f1.mean()

weighted_f1 = np.average(
    f1,
    weights=support,
)


print("\n=== V4-A FULL VALIDATION ===")

print(f"Accuracy        : {accuracy:.6f}")

print(f"Macro Precision : {macro_precision:.6f}")

print(f"Macro Recall    : {macro_recall:.6f}")

print(f"Macro F1        : {macro_f1:.6f}")

print(f"Weighted F1     : {weighted_f1:.6f}")


# ============================================================
# 5. Per-class
# ============================================================

per_class_v4a = pd.DataFrame(
    {
        "label_id": np.arange(N_CLASSES),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "support": support.astype(np.int64),
    }
)


print("\n=== PER CLASS ===")

print(
    per_class_v4a.to_string(
        index=False,
        float_format=lambda x: f"{x:.6f}",
    )
)


# ============================================================
# 6. Misclassification
# ============================================================

errors = []


for true_id in range(N_CLASSES):
    for pred_id in range(N_CLASSES):
        if true_id == pred_id:
            continue

        count = int(
            cm_v4a[
                true_id,
                pred_id,
            ]
        )

        if count > 0:
            errors.append(
                {
                    "true_id": true_id,
                    "pred_id": pred_id,
                    "count": count,
                }
            )


errors_df = (
    pd.DataFrame(errors)
    .sort_values(
        "count",
        ascending=False,
    )
    .reset_index(drop=True)
)


print("\n=== TOP 20 ERRORS ===")

print(errors_df.head(20).to_string(index=False))


# ============================================================
# 7. Save
# ============================================================

metrics_v4a = pd.DataFrame(
    [
        {
            "model": "LightGBM Top40 V4-A",
            "accuracy": accuracy,
            "macro_precision": macro_precision,
            "macro_recall": macro_recall,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "train_patterns": 1_946_494,
            "weight_strategy": "sqrt_frequency",
            "benign_sampling": 1_000_000,
            "validation_rows": total_rows,
        }
    ]
)


metrics_v4a.to_csv(
    V4A_RESULT_DIR / "metrics.csv",
    index=False,
)


per_class_v4a.to_csv(
    V4A_RESULT_DIR / "per_class_metrics.csv",
    index=False,
)


errors_df.to_csv(
    V4A_RESULT_DIR / "misclassifications.csv",
    index=False,
)


pd.DataFrame(cm_v4a).to_csv(
    V4A_RESULT_DIR / "confusion_matrix.csv",
    index=False,
)


print("\nSaved:", V4A_RESULT_DIR)
```

## model_sample_v4.ipynb cell 72

```python
import numpy as np
import pandas as pd
import lightgbm as lgb
import gc
import time

from pathlib import Path
from sklearn.metrics import confusion_matrix


# ============================================================
# 1. V4-B1 모델
# ============================================================

model_v4b1 = lgb.Booster(model_file=str(V4B1_MODEL_PATH))

assert model_v4b1.num_feature() == 40

print("Loaded:", V4B1_MODEL_PATH)
print("Features:", model_v4b1.num_feature())


# ============================================================
# 2. 결과 경로
# ============================================================

V4B1_RESULT_DIR = PROJECT_ROOT / "results" / "lightgbm_top40_v4b1"

V4B1_RESULT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# 3. Full Valid streaming evaluation
# ============================================================

N_CLASSES = 15
BATCH_SIZE = 100_000

cm_b1 = np.zeros(
    (N_CLASSES, N_CLASSES),
    dtype=np.int64,
)

total_rows = 0
correct_rows = 0


valid_select_sql = ", ".join([quote_identifier(f) for f in TOP40_FEATURES] + ["label_id"])


reader = con.execute(
    f"""
    SELECT
        {valid_select_sql}
    FROM read_parquet(
        '{VALID_TOP40_PATH}'
    )
    """
).fetch_record_batch(rows_per_batch=BATCH_SIZE)


start = time.perf_counter()


for batch_id, batch in enumerate(
    reader,
    start=1,
):
    batch_df = batch.to_pandas()

    X_batch = batch_df[TOP40_FEATURES].to_numpy(
        dtype=np.float32,
        copy=False,
    )

    y_batch = batch_df["label_id"].to_numpy(
        dtype=np.int16,
        copy=False,
    )

    proba = model_v4b1.predict(
        X_batch,
        num_threads=2,
    )

    pred = np.argmax(
        proba,
        axis=1,
    ).astype(np.int16)

    cm_b1 += confusion_matrix(
        y_batch,
        pred,
        labels=np.arange(N_CLASSES),
    )

    total_rows += len(y_batch)

    correct_rows += int(np.sum(pred == y_batch))

    if batch_id == 1 or batch_id % 5 == 0:
        print(
            f"[batch {batch_id:02d}] rows={total_rows:,} accuracy={correct_rows / total_rows:.6f}"
        )

    del (
        batch_df,
        X_batch,
        y_batch,
        proba,
        pred,
    )

    gc.collect()


eval_elapsed = time.perf_counter() - start


print("\nValidation rows:", f"{total_rows:,}")

print("Evaluation time:", f"{eval_elapsed:.1f}s")

assert total_rows == 2_390_002


# ============================================================
# 4. Metrics
# ============================================================

tp = np.diag(cm_b1).astype(np.float64)

support = cm_b1.sum(axis=1).astype(np.float64)

predicted = cm_b1.sum(axis=0).astype(np.float64)


precision = np.divide(
    tp,
    predicted,
    out=np.zeros_like(tp),
    where=predicted != 0,
)

recall = np.divide(
    tp,
    support,
    out=np.zeros_like(tp),
    where=support != 0,
)

f1 = np.divide(
    2 * precision * recall,
    precision + recall,
    out=np.zeros_like(tp),
    where=(precision + recall) != 0,
)


accuracy = tp.sum() / support.sum()

macro_precision = precision.mean()
macro_recall = recall.mean()
macro_f1 = f1.mean()

weighted_f1 = np.average(
    f1,
    weights=support,
)


print("\n=== V4-B1 FULL VALIDATION ===")

print(f"Accuracy        : {accuracy:.6f}")
print(f"Macro Precision : {macro_precision:.6f}")
print(f"Macro Recall    : {macro_recall:.6f}")
print(f"Macro F1        : {macro_f1:.6f}")
print(f"Weighted F1     : {weighted_f1:.6f}")


# ============================================================
# 5. Per-class
# ============================================================

per_class_b1 = pd.DataFrame(
    {
        "label_id": np.arange(N_CLASSES),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "support": support.astype(np.int64),
    }
)


print("\n=== FOCUS CLASSES ===")

print(
    per_class_b1[per_class_b1["label_id"].isin([0, 9, 11, 12])].to_string(
        index=False,
        float_format=lambda x: f"{x:.6f}",
    )
)


# ============================================================
# 6. Misclassification
# ============================================================

errors = []

for true_id in range(N_CLASSES):
    for pred_id in range(N_CLASSES):
        if true_id == pred_id:
            continue

        count = int(
            cm_b1[
                true_id,
                pred_id,
            ]
        )

        if count > 0:
            errors.append(
                {
                    "true_id": true_id,
                    "pred_id": pred_id,
                    "count": count,
                }
            )


errors_b1 = (
    pd.DataFrame(errors)
    .sort_values(
        "count",
        ascending=False,
    )
    .reset_index(drop=True)
)


print("\n=== TOP 20 ERRORS ===")

print(errors_b1.head(20).to_string(index=False))


# ============================================================
# 7. 저장
# ============================================================

metrics_b1 = pd.DataFrame(
    [
        {
            "model": "LightGBM Top40 V4-B1",
            "accuracy": accuracy,
            "macro_precision": macro_precision,
            "macro_recall": macro_recall,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "train_patterns": 1_946_494,
            "weight_strategy": "sqrt_frequency",
            "infilteration_correction": 2.0,
            "validation_rows": total_rows,
        }
    ]
)


metrics_b1.to_csv(
    V4B1_RESULT_DIR / "metrics.csv",
    index=False,
)

per_class_b1.to_csv(
    V4B1_RESULT_DIR / "per_class_metrics.csv",
    index=False,
)

errors_b1.to_csv(
    V4B1_RESULT_DIR / "misclassifications.csv",
    index=False,
)

pd.DataFrame(cm_b1).to_csv(
    V4B1_RESULT_DIR / "confusion_matrix.csv",
    index=False,
)


print("\nSaved:", V4B1_RESULT_DIR)


# ============================================================
# 8. V4-A vs V4-B1 자동 비교
# ============================================================

metrics_a = pd.read_csv(PROJECT_ROOT / "results" / "lightgbm_top40_v4a" / "metrics.csv")

per_class_a = pd.read_csv(PROJECT_ROOT / "results" / "lightgbm_top40_v4a" / "per_class_metrics.csv")


comparison = pd.DataFrame(
    {
        "metric": [
            "accuracy",
            "macro_precision",
            "macro_recall",
            "macro_f1",
            "weighted_f1",
        ],
        "V4-A": [
            float(metrics_a.iloc[0]["accuracy"]),
            float(metrics_a.iloc[0]["macro_precision"]),
            float(metrics_a.iloc[0]["macro_recall"]),
            float(metrics_a.iloc[0]["macro_f1"]),
            float(metrics_a.iloc[0]["weighted_f1"]),
        ],
        "V4-B1": [
            accuracy,
            macro_precision,
            macro_recall,
            macro_f1,
            weighted_f1,
        ],
    }
)

comparison["delta"] = comparison["V4-B1"] - comparison["V4-A"]


print("\n=== V4-A vs V4-B1 ===")

print(
    comparison.to_string(
        index=False,
        float_format=lambda x: f"{x:.6f}",
    )
)


# ============================================================
# 9. Focus class A/B 비교
# ============================================================

focus_ids = [0, 9, 11, 12]

focus_compare = per_class_a[per_class_a["label_id"].isin(focus_ids)][
    [
        "label_id",
        "precision",
        "recall",
        "f1",
    ]
].merge(
    per_class_b1[per_class_b1["label_id"].isin(focus_ids)][
        [
            "label_id",
            "precision",
            "recall",
            "f1",
        ]
    ],
    on="label_id",
    suffixes=(
        "_v4a",
        "_v4b1",
    ),
)


for metric in [
    "precision",
    "recall",
    "f1",
]:
    focus_compare[f"{metric}_delta"] = (
        focus_compare[f"{metric}_v4b1"] - focus_compare[f"{metric}_v4a"]
    )


print("\n=== FOCUS CLASS COMPARISON ===")

print(
    focus_compare.to_string(
        index=False,
        float_format=lambda x: f"{x:.6f}",
    )
)
```

## model_sample_v4.ipynb cell 81

```python
import numpy as np
import pandas as pd
import lightgbm as lgb
import gc
import time

from pathlib import Path
from sklearn.metrics import confusion_matrix


# ============================================================
# 0. 설정
# ============================================================

N_CLASSES = 15
BATCH_SIZE = 100_000

V4B2_MODEL_PATH = PROJECT_ROOT / "models" / "network" / "lightgbm_top40_v4b2.txt"

V4B2_RESULT_DIR = PROJECT_ROOT / "results" / "lightgbm_top40_v4b2"

V4B2_RESULT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# 1. V4-B2 모델 로드
# ============================================================

model_v4b2 = lgb.Booster(model_file=str(V4B2_MODEL_PATH))

print("Loaded:", V4B2_MODEL_PATH)
print("Features:", model_v4b2.num_feature())

assert model_v4b2.num_feature() == 40


# ============================================================
# 2. Confusion Matrix 초기화
# ============================================================

cm_b2 = np.zeros(
    (N_CLASSES, N_CLASSES),
    dtype=np.int64,
)

total_rows = 0
correct_rows = 0


# ============================================================
# 3. Validation SELECT 준비
# ============================================================

valid_select_sql = ", ".join(
    [quote_identifier(feature) for feature in TOP40_FEATURES] + ["label_id"]
)


# ============================================================
# 4. Arrow Streaming Reader
#
# fetch_record_batch()가 deprecated 되었으므로
# 이번에는 to_arrow_reader() 사용
# ============================================================

reader = con.execute(
    f"""
    SELECT
        {valid_select_sql}
    FROM read_parquet(
        '{VALID_TOP40_PATH}'
    )
    """
).to_arrow_reader(batch_size=BATCH_SIZE)


# ============================================================
# 5. Full Valid Streaming Evaluation
# ============================================================

start = time.perf_counter()


for batch_id, batch in enumerate(
    reader,
    start=1,
):
    batch_df = batch.to_pandas()

    X_batch = batch_df[TOP40_FEATURES].to_numpy(
        dtype=np.float32,
        copy=False,
    )

    y_batch = batch_df["label_id"].to_numpy(
        dtype=np.int16,
        copy=False,
    )

    # --------------------------------------------------------
    # Predict
    # --------------------------------------------------------

    proba = model_v4b2.predict(
        X_batch,
        num_threads=4,
    )

    pred = np.argmax(
        proba,
        axis=1,
    ).astype(np.int16)

    # --------------------------------------------------------
    # Confusion Matrix 누적
    # --------------------------------------------------------

    cm_b2 += confusion_matrix(
        y_batch,
        pred,
        labels=np.arange(N_CLASSES),
    )

    total_rows += len(y_batch)

    correct_rows += int(np.sum(pred == y_batch))

    if batch_id == 1 or batch_id % 5 == 0:
        print(
            f"[batch {batch_id:02d}] rows={total_rows:,} accuracy={correct_rows / total_rows:.6f}"
        )

    # --------------------------------------------------------
    # 메모리 해제
    # --------------------------------------------------------

    del (
        batch_df,
        X_batch,
        y_batch,
        proba,
        pred,
    )

    gc.collect()


eval_elapsed = time.perf_counter() - start


print()
print("Validation rows:", f"{total_rows:,}")

print("Evaluation time:", f"{eval_elapsed:.1f}s")


assert total_rows == 2_390_002


# ============================================================
# 6. Overall Metrics
# ============================================================

tp = np.diag(cm_b2).astype(np.float64)


support = cm_b2.sum(axis=1).astype(np.float64)


predicted = cm_b2.sum(axis=0).astype(np.float64)


precision = np.divide(
    tp,
    predicted,
    out=np.zeros_like(tp),
    where=predicted != 0,
)


recall = np.divide(
    tp,
    support,
    out=np.zeros_like(tp),
    where=support != 0,
)


f1 = np.divide(
    2 * precision * recall,
    precision + recall,
    out=np.zeros_like(tp),
    where=(precision + recall) != 0,
)


accuracy = tp.sum() / support.sum()

macro_precision = precision.mean()

macro_recall = recall.mean()

macro_f1 = f1.mean()

weighted_f1 = np.average(
    f1,
    weights=support,
)


print()
print("=== V4-B2 FULL VALIDATION ===")

print(f"Accuracy        : {accuracy:.6f}")

print(f"Macro Precision : {macro_precision:.6f}")

print(f"Macro Recall    : {macro_recall:.6f}")

print(f"Macro F1        : {macro_f1:.6f}")

print(f"Weighted F1     : {weighted_f1:.6f}")


# ============================================================
# 7. Per-Class Metrics
# ============================================================

per_class_b2 = pd.DataFrame(
    {
        "label_id": np.arange(N_CLASSES),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "support": support.astype(np.int64),
    }
)


print()
print("=== PER CLASS ===")

print(
    per_class_b2.to_string(
        index=False,
        float_format=lambda x: f"{x:.6f}",
    )
)


# ============================================================
# 8. Focus Classes
# ============================================================

FOCUS_IDS = [
    0,  # Benign
    9,  # SlowHTTPTest
    11,  # FTP-BruteForce
    12,  # Infilteration
]


print()
print("=== FOCUS CLASSES ===")

print(
    per_class_b2[per_class_b2["label_id"].isin(FOCUS_IDS)].to_string(
        index=False,
        float_format=lambda x: f"{x:.6f}",
    )
)


# ============================================================
# 9. Misclassification 생성
# ============================================================

errors = []


for true_id in range(N_CLASSES):
    for pred_id in range(N_CLASSES):
        if true_id == pred_id:
            continue

        count = int(
            cm_b2[
                true_id,
                pred_id,
            ]
        )

        if count > 0:
            errors.append(
                {
                    "true_id": true_id,
                    "pred_id": pred_id,
                    "count": count,
                }
            )


errors_b2 = (
    pd.DataFrame(errors)
    .sort_values(
        "count",
        ascending=False,
    )
    .reset_index(drop=True)
)


print()
print("=== TOP 20 ERRORS ===")

print(errors_b2.head(20).to_string(index=False))


# ============================================================
# 10. Critical Pair Errors
# ============================================================

critical_b2 = errors_b2[
    ((errors_b2["true_id"] == 0) & (errors_b2["pred_id"] == 12))
    | ((errors_b2["true_id"] == 12) & (errors_b2["pred_id"] == 0))
    | ((errors_b2["true_id"] == 9) & (errors_b2["pred_id"] == 11))
    | ((errors_b2["true_id"] == 11) & (errors_b2["pred_id"] == 9))
]


print()
print("=== CRITICAL PAIR ERRORS ===")

print(critical_b2.to_string(index=False))


# ============================================================
# 11. B2 결과 저장
# ============================================================

metrics_b2 = pd.DataFrame(
    [
        {
            "model": "LightGBM Top40 V4-B2",
            "accuracy": accuracy,
            "macro_precision": macro_precision,
            "macro_recall": macro_recall,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "train_patterns": 1_946_494,
            "weight_strategy": "sqrt_frequency",
            "infilteration_correction": 3.0,
            "validation_rows": total_rows,
            "evaluation_seconds": eval_elapsed,
        }
    ]
)


metrics_b2.to_csv(
    V4B2_RESULT_DIR / "metrics.csv",
    index=False,
)


per_class_b2.to_csv(
    V4B2_RESULT_DIR / "per_class_metrics.csv",
    index=False,
)


errors_b2.to_csv(
    V4B2_RESULT_DIR / "misclassifications.csv",
    index=False,
)


pd.DataFrame(cm_b2).to_csv(
    V4B2_RESULT_DIR / "confusion_matrix.csv",
    index=False,
)


print()
print("Saved:", V4B2_RESULT_DIR)


# ============================================================
# 12. 기존 V4-A / V4-B1 결과 읽기
# ============================================================

V4A_RESULT_DIR = PROJECT_ROOT / "results" / "lightgbm_top40_v4a"

V4B1_RESULT_DIR = PROJECT_ROOT / "results" / "lightgbm_top40_v4b1"


metrics_a = pd.read_csv(V4A_RESULT_DIR / "metrics.csv")

metrics_b1 = pd.read_csv(V4B1_RESULT_DIR / "metrics.csv")


per_class_a = pd.read_csv(V4A_RESULT_DIR / "per_class_metrics.csv")

per_class_b1 = pd.read_csv(V4B1_RESULT_DIR / "per_class_metrics.csv")


# ============================================================
# 13. A / B1 / B2 Overall 비교
# ============================================================

overall_compare = pd.DataFrame(
    {
        "metric": [
            "accuracy",
            "macro_precision",
            "macro_recall",
            "macro_f1",
            "weighted_f1",
        ],
        "V4-A_x1": [
            float(metrics_a.iloc[0]["accuracy"]),
            float(metrics_a.iloc[0]["macro_precision"]),
            float(metrics_a.iloc[0]["macro_recall"]),
            float(metrics_a.iloc[0]["macro_f1"]),
            float(metrics_a.iloc[0]["weighted_f1"]),
        ],
        "V4-B1_x2": [
            float(metrics_b1.iloc[0]["accuracy"]),
            float(metrics_b1.iloc[0]["macro_precision"]),
            float(metrics_b1.iloc[0]["macro_recall"]),
            float(metrics_b1.iloc[0]["macro_f1"]),
            float(metrics_b1.iloc[0]["weighted_f1"]),
        ],
        "V4-B2_x3": [
            accuracy,
            macro_precision,
            macro_recall,
            macro_f1,
            weighted_f1,
        ],
    }
)


overall_compare["B1_minus_A"] = overall_compare["V4-B1_x2"] - overall_compare["V4-A_x1"]


overall_compare["B2_minus_B1"] = overall_compare["V4-B2_x3"] - overall_compare["V4-B1_x2"]


print()
print("=== V4-A / B1 / B2 OVERALL ===")

print(
    overall_compare.to_string(
        index=False,
        float_format=lambda x: f"{x:.6f}",
    )
)


# ============================================================
# 14. Focus Class A / B1 / B2 비교
# ============================================================

focus_a = per_class_a[per_class_a["label_id"].isin(FOCUS_IDS)][
    [
        "label_id",
        "precision",
        "recall",
        "f1",
    ]
].rename(
    columns={
        "precision": "precision_A",
        "recall": "recall_A",
        "f1": "f1_A",
    }
)


focus_b1 = per_class_b1[per_class_b1["label_id"].isin(FOCUS_IDS)][
    [
        "label_id",
        "precision",
        "recall",
        "f1",
    ]
].rename(
    columns={
        "precision": "precision_B1",
        "recall": "recall_B1",
        "f1": "f1_B1",
    }
)


focus_b2 = per_class_b2[per_class_b2["label_id"].isin(FOCUS_IDS)][
    [
        "label_id",
        "precision",
        "recall",
        "f1",
    ]
].rename(
    columns={
        "precision": "precision_B2",
        "recall": "recall_B2",
        "f1": "f1_B2",
    }
)


focus_compare = focus_a.merge(
    focus_b1,
    on="label_id",
).merge(
    focus_b2,
    on="label_id",
)


focus_compare["recall_B2_minus_B1"] = focus_compare["recall_B2"] - focus_compare["recall_B1"]


focus_compare["f1_B2_minus_B1"] = focus_compare["f1_B2"] - focus_compare["f1_B1"]


print()
print("=== FOCUS CLASS A / B1 / B2 ===")

print(
    focus_compare.to_string(
        index=False,
        float_format=lambda x: f"{x:.6f}",
    )
)


# ============================================================
# 15. 비교 결과 저장
# ============================================================

COMPARE_DIR = PROJECT_ROOT / "results" / "v4_model_comparison"

COMPARE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


overall_compare.to_csv(
    COMPARE_DIR / "overall_metrics.csv",
    index=False,
)


focus_compare.to_csv(
    COMPARE_DIR / "focus_class_metrics.csv",
    index=False,
)


print()
print("Comparison saved:", COMPARE_DIR)
```
