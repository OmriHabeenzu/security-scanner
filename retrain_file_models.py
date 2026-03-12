"""
Retrain ML models using file-based features.

The existing models were trained on NSL-KDD network-traffic features (41 cols)
but file_scanner.py extracts 41 *file-analysis* features at inference time.
This mismatch made every prediction meaningless.

This script generates a realistic synthetic dataset whose feature vectors
exactly mirror extract_file_features(), trains RF / DT / SVM on it,
and saves the new .pkl files to ml_models/.
"""

import numpy as np
import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# ── Feature index reference (must match extract_file_features in file_scanner.py) ──
# 0  size_kb
# 1  is_gt_1mb
# 2  is_gt_10mb
# 3  is_lt_1kb
# 4  filename_length
# 5  is_executable_ext
# 6  is_script_ext
# 7  is_archive_ext
# 8  is_document_ext
# 9  is_exe
# 10 is_dll
# 11 is_bat_cmd
# 12 is_vbs_js
# 13 is_text_type
# 14 is_image_type
# 15 has_http
# 16 has_https
# 17 has_eval
# 18 has_exec
# 19 has_cmd_powershell
# 20 has_script_tag
# 21 null_byte_ratio
# 22 byte_diversity
# 23 has_mz_header
# 24 has_pk_header
# 25-40 padding zeros

N_FEATURES = 41
rng = np.random.default_rng(42)


def _zero():
    return np.zeros(N_FEATURES)


# ── Malicious sample generators ──────────────────────────────────────────────

def gen_exe_malware(n):
    """PE executables / DLLs with suspicious content."""
    samples = []
    for _ in range(n):
        f = _zero()
        size_kb = rng.uniform(50, 8000)
        f[0]  = size_kb
        f[1]  = 1 if size_kb > 1024 else 0
        f[2]  = 1 if size_kb > 10240 else 0
        f[3]  = 0
        f[4]  = rng.integers(8, 25)
        f[5]  = 1   # executable ext
        f[9]  = rng.choice([1, 0], p=[0.7, 0.3])   # .exe
        f[10] = 1 - f[9]                             # .dll
        f[15] = rng.choice([0, 1], p=[0.4, 0.6])    # http
        f[16] = rng.choice([0, 1], p=[0.5, 0.5])    # https
        f[19] = rng.choice([0, 1], p=[0.2, 0.8])    # cmd/powershell
        f[21] = rng.uniform(0.10, 0.45)              # null byte ratio (packed)
        f[22] = rng.uniform(0.40, 0.70)              # byte diversity
        f[23] = 1                                     # MZ header
        samples.append(f)
    return np.array(samples)


def gen_script_malware(n):
    """VBScript / JS files with eval/exec and phishing links."""
    samples = []
    for _ in range(n):
        f = _zero()
        size_kb = rng.uniform(1, 500)
        f[0]  = size_kb
        f[3]  = 1 if size_kb < 1 else 0
        f[4]  = rng.integers(6, 30)
        f[5]  = 1
        f[6]  = 1
        f[12] = 1   # vbs/js
        f[15] = 1   # http
        f[16] = rng.choice([0, 1])
        f[17] = rng.choice([0, 1], p=[0.2, 0.8])    # eval(
        f[18] = rng.choice([0, 1], p=[0.3, 0.7])    # exec(
        f[20] = rng.choice([0, 1], p=[0.4, 0.6])    # <script
        f[21] = rng.uniform(0.0, 0.05)
        f[22] = rng.uniform(0.12, 0.30)
        samples.append(f)
    return np.array(samples)


def gen_batch_malware(n):
    """Batch/CMD files that invoke cmd.exe or PowerShell."""
    samples = []
    for _ in range(n):
        f = _zero()
        size_kb = rng.uniform(0.5, 100)
        f[0]  = size_kb
        f[3]  = 1 if size_kb < 1 else 0
        f[4]  = rng.integers(5, 20)
        f[5]  = 1
        f[11] = 1   # bat/cmd
        f[19] = 1   # cmd/powershell
        f[18] = rng.choice([0, 1], p=[0.5, 0.5])
        f[21] = rng.uniform(0.0, 0.02)
        f[22] = rng.uniform(0.08, 0.20)
        samples.append(f)
    return np.array(samples)


def gen_downloader(n):
    """Executables that embed download URLs."""
    samples = []
    for _ in range(n):
        f = _zero()
        size_kb = rng.uniform(20, 3000)
        f[0]  = size_kb
        f[1]  = 1 if size_kb > 1024 else 0
        f[4]  = rng.integers(8, 20)
        f[5]  = 1
        f[9]  = 1
        f[15] = 1
        f[16] = 1
        f[19] = rng.choice([0, 1], p=[0.4, 0.6])
        f[21] = rng.uniform(0.05, 0.35)
        f[22] = rng.uniform(0.50, 0.80)
        f[23] = 1
        samples.append(f)
    return np.array(samples)


def gen_malicious_doc(n):
    """Office/PDF documents with embedded script tags or macros."""
    samples = []
    for _ in range(n):
        f = _zero()
        size_kb = rng.uniform(10, 2000)
        f[0]  = size_kb
        f[1]  = 1 if size_kb > 1024 else 0
        f[4]  = rng.integers(8, 30)
        f[8]  = 1   # document ext
        f[15] = rng.choice([0, 1], p=[0.5, 0.5])
        f[17] = rng.choice([0, 1], p=[0.4, 0.6])    # eval(
        f[18] = rng.choice([0, 1], p=[0.4, 0.6])    # exec(
        f[20] = rng.choice([0, 1], p=[0.3, 0.7])    # <script
        f[21] = rng.uniform(0.0, 0.10)
        f[22] = rng.uniform(0.20, 0.50)
        f[24] = rng.choice([0, 1])                   # zip-based (docx)
        samples.append(f)
    return np.array(samples)


# ── Clean sample generators ───────────────────────────────────────────────────

def gen_text_file(n):
    """Plain text, CSV, log files — no suspicious content."""
    samples = []
    for _ in range(n):
        f = _zero()
        size_kb = rng.uniform(1, 2000)
        f[0]  = size_kb
        f[1]  = 1 if size_kb > 1024 else 0
        f[4]  = rng.integers(5, 25)
        f[13] = 1   # text type
        f[15] = rng.choice([0, 1], p=[0.8, 0.2])    # occasional URL in text
        f[21] = rng.uniform(0.0, 0.005)              # almost no null bytes
        f[22] = rng.uniform(0.08, 0.25)              # typical ASCII diversity
        samples.append(f)
    return np.array(samples)


def gen_image_file(n):
    """PNG / JPG / GIF images — high byte diversity, no scripts."""
    samples = []
    for _ in range(n):
        f = _zero()
        size_kb = rng.uniform(10, 5000)
        f[0]  = size_kb
        f[1]  = 1 if size_kb > 1024 else 0
        f[4]  = rng.integers(5, 20)
        f[14] = 1   # image type
        f[21] = rng.uniform(0.0, 0.02)
        f[22] = rng.uniform(0.60, 0.95)              # images have high diversity
        samples.append(f)
    return np.array(samples)


def gen_clean_doc(n):
    """Legitimate PDFs and Office documents."""
    samples = []
    for _ in range(n):
        f = _zero()
        size_kb = rng.uniform(50, 5000)
        f[0]  = size_kb
        f[1]  = 1 if size_kb > 1024 else 0
        f[4]  = rng.integers(8, 35)
        f[8]  = 1   # document ext
        f[15] = rng.choice([0, 1], p=[0.6, 0.4])    # docs often have links
        f[16] = rng.choice([0, 1], p=[0.5, 0.5])
        f[21] = rng.uniform(0.0, 0.08)
        f[22] = rng.uniform(0.20, 0.50)
        f[24] = rng.choice([0, 1])                   # docx uses zip
        samples.append(f)
    return np.array(samples)


def gen_clean_archive(n):
    """Legitimate ZIP / RAR archives."""
    samples = []
    for _ in range(n):
        f = _zero()
        size_kb = rng.uniform(100, 50000)
        f[0]  = size_kb
        f[1]  = 1 if size_kb > 1024 else 0
        f[2]  = 1 if size_kb > 10240 else 0
        f[4]  = rng.integers(5, 25)
        f[7]  = 1   # archive ext
        f[21] = rng.uniform(0.0, 0.01)
        f[22] = rng.uniform(0.70, 0.98)
        f[24] = rng.choice([0, 1], p=[0.3, 0.7])    # ZIP header
        samples.append(f)
    return np.array(samples)


def gen_clean_script(n):
    """Legitimate Python / shell scripts — no malicious patterns."""
    samples = []
    for _ in range(n):
        f = _zero()
        size_kb = rng.uniform(1, 200)
        f[0]  = size_kb
        f[4]  = rng.integers(5, 30)
        f[6]  = 1   # script ext
        f[13] = 1   # text type
        f[15] = rng.choice([0, 1], p=[0.5, 0.5])    # scripts often import URLs
        f[16] = rng.choice([0, 1], p=[0.4, 0.6])
        # eval/exec appear in benign scripts too — add realistic noise
        f[17] = rng.choice([0, 1], p=[0.7, 0.3])
        f[18] = rng.choice([0, 1], p=[0.6, 0.4])
        f[21] = rng.uniform(0.0, 0.003)
        f[22] = rng.uniform(0.08, 0.22)
        samples.append(f)
    return np.array(samples)


# ── Dataset assembly ──────────────────────────────────────────────────────────

def build_dataset(n_per_type=600):
    print(f"Generating {n_per_type} samples per class type ...")

    mal = np.vstack([
        gen_exe_malware(n_per_type),
        gen_script_malware(n_per_type),
        gen_batch_malware(n_per_type),
        gen_downloader(n_per_type),
        gen_malicious_doc(n_per_type),
    ])
    y_mal = np.ones(len(mal), dtype=int)

    clean = np.vstack([
        gen_text_file(n_per_type),
        gen_image_file(n_per_type),
        gen_clean_doc(n_per_type),
        gen_clean_archive(n_per_type),
        gen_clean_script(n_per_type),
    ])
    y_clean = np.zeros(len(clean), dtype=int)

    X = np.vstack([mal, clean])
    y = np.concatenate([y_mal, y_clean])

    # Shuffle
    idx = rng.permutation(len(X))
    return X[idx], y[idx]


# ── Training ──────────────────────────────────────────────────────────────────

def train_and_save(output_dir='ml_models'):
    os.makedirs(output_dir, exist_ok=True)

    X, y = build_dataset(n_per_type=600)
    print(f"Dataset: {X.shape[0]} samples, {X.shape[1]} features  "
          f"| Malicious: {y.sum()}  Clean: {(y==0).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    results = {}

    # ── Random Forest ────────────────────────────────────────────────────────
    print("\n=== Training Random Forest ===")
    rf = RandomForestClassifier(n_estimators=150, max_depth=20,
                                random_state=42, n_jobs=-1)
    rf.fit(X_train_s, y_train)
    acc = accuracy_score(y_test, rf.predict(X_test_s))
    results['random_forest'] = acc
    print(f"Random Forest Accuracy: {acc*100:.2f}%")
    print(classification_report(y_test, rf.predict(X_test_s),
                                 target_names=['Clean', 'Malicious']))

    # ── Decision Tree ────────────────────────────────────────────────────────
    print("\n=== Training Decision Tree ===")
    dt = DecisionTreeClassifier(max_depth=20, random_state=42)
    dt.fit(X_train_s, y_train)
    acc = accuracy_score(y_test, dt.predict(X_test_s))
    results['decision_tree'] = acc
    print(f"Decision Tree Accuracy: {acc*100:.2f}%")
    print(classification_report(y_test, dt.predict(X_test_s),
                                 target_names=['Clean', 'Malicious']))

    # ── SVM (subset for speed) ───────────────────────────────────────────────
    print("\n=== Training SVM ===")
    subset = min(8000, len(X_train_s))
    idx = rng.choice(len(X_train_s), subset, replace=False)
    svm = SVC(kernel='rbf', probability=True, random_state=42)
    svm.fit(X_train_s[idx], y_train[idx])
    acc = accuracy_score(y_test, svm.predict(X_test_s))
    results['svm'] = acc
    print(f"SVM Accuracy: {acc*100:.2f}%")
    print(classification_report(y_test, svm.predict(X_test_s),
                                 target_names=['Clean', 'Malicious']))

    # ── Save ─────────────────────────────────────────────────────────────────
    print(f"\nSaving models to {output_dir}/ ...")
    joblib.dump(rf,     os.path.join(output_dir, 'random_forest.pkl'))
    joblib.dump(dt,     os.path.join(output_dir, 'decision_tree.pkl'))
    joblib.dump(svm,    os.path.join(output_dir, 'svm.pkl'))
    joblib.dump(scaler, os.path.join(output_dir, 'scaler.pkl'))

    print("\n=== TRAINING COMPLETE ===")
    for model, acc in results.items():
        print(f"  {model:20s}: {acc*100:.2f}%")
    print("Models saved successfully!")


if __name__ == '__main__':
    train_and_save()
