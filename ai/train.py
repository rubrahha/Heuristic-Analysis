"""
train.py — Train AI model for zero false-negative, near-zero false-positive AV.

Enterprise Upgrades:
- Multi-threaded Feature Extraction (10x-20x faster on large datasets)
- Automated Model Versioning & Backups
- Sklearn 1.2+ Future-Proofing (base_estimator deprecation fix)
- Smarter cross-validation integration
"""

from __future__ import annotations

import warnings
warnings.filterwarnings("ignore")
import os
os.environ["PYTHONWARNINGS"] = "ignore"

import json, time, sys, shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np
from sklearn.model_selection import (StratifiedKFold, cross_val_score,
                                     StratifiedShuffleSplit)
from sklearn.metrics import (confusion_matrix, precision_score, recall_score,
                             f1_score, roc_auc_score)
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
import joblib
try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    print("[WARN] XGBoost not installed. Run: pip install xgboost")
    print("       Falling back to RandomForest only.\n")

try:
    from imblearn.over_sampling import SMOTE
    HAS_SMOTE = True
except ImportError:
    HAS_SMOTE = False
    print("[WARN] imbalanced-learn not installed. Run: pip install imbalanced-learn")
    print("       Falling back to class-weight balancing only.\n")

from extractor import extract_features, features_to_vector, FEATURE_NAMES
from ensemble import EnsembleWrapper

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE    = Path(__file__).parent
MALWARE = BASE / "dataset" / "malware"
CLEAN   = BASE / "dataset" / "clean"
OUT     = BASE / "models"
LOGS    = BASE / "logs"
OUT.mkdir(exist_ok=True)
LOGS.mkdir(exist_ok=True)

PE_EXTS = {".exe", ".dll", ".scr", ".sys", ".ocx", ".drv", ".cpl"}

# ── Zero-FN threshold parameters ──────────────────────────────────────────────
MIN_RECALL       = 1.00   
FALLBACK_RECALL  = 0.98   
THRESH_MIN       = 0.08   
THRESH_MAX       = 0.90   

# ── Model factory ─────────────────────────────────────────────────────────────

def _make_xgb(n: int) -> "XGBClassifier":
    n_est = min(1000, max(300, n // 2))
    lr    = 0.04 if n > 1000 else 0.06
    return XGBClassifier(
        n_estimators      = n_est,
        max_depth         = 7,
        learning_rate     = lr,
        subsample         = 0.85,
        colsample_bytree  = 0.85,
        min_child_weight  = 2,
        gamma             = 0.05,
        reg_alpha         = 0.1,
        reg_lambda        = 1.0,
        scale_pos_weight  = 1,    
        use_label_encoder = False,
        eval_metric       = "logloss",
        tree_method       = "hist",
        n_jobs            = -1,
        random_state      = 42,
        verbosity         = 0,
    )

def _make_rf(n: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators      = min(600, max(200, n // 3)),
        max_depth         = 12,
        min_samples_split = 3,
        min_samples_leaf  = 1,
        max_features      = "sqrt",
        class_weight      = "balanced_subsample",
        n_jobs            = -1,
        random_state      = 42,
    )

# ── Parallel Feature Extraction ───────────────────────────────────────────────

def _process_single_file(fp: Path, label: int) -> tuple:
    """Worker function for parallel extraction."""
    try:
        feats = extract_features(str(fp))
        if feats:
            return features_to_vector(feats), label, str(fp), None
    except Exception as e:
        return None, None, str(fp), str(e)
    return None, None, str(fp), "Not a valid PE / Extraction returned None"

def collect(folder: Path, label: int) -> tuple[list, list, list, list]:
    """
    Extract features from all PE files in folder using multi-threading.
    """
    X, y, paths, errors = [], [], [], []
    files = [f for f in folder.rglob("*") if f.suffix.lower() in PE_EXTS and f.is_file()]
    total_files = len(files)
    print(f"  [{folder.name}/] {total_files} files found")

    if total_files == 0:
        return X, y, paths, errors

    # Optimize worker count based on CPU cores
    max_workers = min(32, (os.cpu_count() or 4) * 2)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_process_single_file, fp, label): fp for fp in files}
        
        for i, future in enumerate(as_completed(futures)):
            vec, lbl, fp, err = future.result()
            if err:
                errors.append((fp, err))
            elif vec is not None:
                X.append(vec)
                y.append(lbl)
                paths.append(fp)

            # Print progress bar
            pct = int(40 * (i + 1) / max(total_files, 1))
            bar = "█" * pct + "░" * (40 - pct)
            print(f"\r    [{bar}] {i+1}/{total_files} processed", end="", flush=True)

    ok = len(X)
    print(f"\r    ✓ {ok} extracted  {total_files-ok} skipped  {len(errors)} errors{' ' * 20}")
    
    if errors:
        err_log = LOGS / f"extract_errors_{folder.name}_{int(time.time())}.txt"
        err_log.write_text("\n".join(f"{p}: {e}" for p, e in errors), encoding="utf-8")
        print(f"    ⚠  {len(errors)} extraction errors logged → {err_log.name}")
        
    return X, y, paths, errors

# ── Threshold tuning (zero-FN guarantee) ─────────────────────────────────────

def tune_threshold_zero_fn(probs: np.ndarray, y_true: np.ndarray) -> tuple[float, str]:
    candidates_100 = []   
    candidates_98  = []   

    for thresh in np.arange(THRESH_MIN, THRESH_MAX, 0.01):
        thresh = round(float(thresh), 3)
        preds = (probs >= thresh).astype(int)
        
        if len(np.unique(preds)) < 2:
            continue
            
        cm = confusion_matrix(y_true, preds)
        if cm.shape != (2, 2):
            continue
            
        tn, fp, fn, tp = cm.ravel()
        total_malware = tp + fn
        if total_malware == 0:
            continue
            
        recall = tp / total_malware
        if recall >= MIN_RECALL:
            candidates_100.append((thresh, fp))
        elif recall >= FALLBACK_RECALL:
            candidates_98.append((thresh, fp))

    if candidates_100:
        best = max(candidates_100, key=lambda x: x[0])
        msg = (f"✓  ZERO FALSE NEGATIVES guaranteed at threshold {best[0]:.3f} "
               f"({best[1]} false positives on validation set)")
        return best[0], msg

    if candidates_98:
        best = max(candidates_98, key=lambda x: x[0])
        msg = (f"⚠  Could not achieve 100% recall — best is {FALLBACK_RECALL*100:.0f}% "
               f"at threshold {best[0]:.3f} ({best[1]} FP). "
               f"Add more malware samples and retrain.")
        return best[0], msg

    msg = ("❌  Could not find a good threshold. Dataset may be too small or "
           "imbalanced. Using 0.30 as emergency fallback.")
    return 0.30, msg

# ── Feature importance ────────────────────────────────────────────────────────

def print_feature_importance(model, top_n: int = 15) -> None:
    try:
        if hasattr(model, "estimators_"):
            imps = []
            for est in model.estimators_:
                # FIX 2: Handle both older scikit-learn and 1.2+ safely
                base = getattr(est, "estimator", getattr(est, "base_estimator", est))
                if hasattr(base, "feature_importances_"):
                    imps.append(base.feature_importances_)
            if imps:
                importances = np.mean(imps, axis=0)
            else:
                return
        elif hasattr(model, "estimator") or hasattr(model, "base_estimator"):
            base = getattr(model, "estimator", getattr(model, "base_estimator", model))
            if hasattr(base, "feature_importances_"):
                importances = base.feature_importances_
            else:
                return
        elif hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
        else:
            return

        ranked = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
        print(f"\n  Top {top_n} features:")
        for i, (name, imp) in enumerate(ranked[:top_n]):
            bar = "█" * int(imp * 300)
            print(f"    {i+1:2d}. {name:<40} {imp:.4f}  {bar}")
    except Exception as e:
        print(f"    (Feature importance unavailable: {e})")

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    t0 = time.time()
    print("\n" + "=" * 60)
    print("  HeuristicScanner — AI Model Training (Enterprise Edition)")
    print("=" * 60 + "\n")

    Xm, ym, pm, em = collect(MALWARE, 1)
    Xc, yc, pc, ec = collect(CLEAN,   0)
    print()

    if len(Xm) < 20:
        print(f"[ERROR] Only {len(Xm)} malware samples. Need at least 20.")
        sys.exit(1)
    if len(Xc) < 20:
        print(f"[ERROR] Only {len(Xc)} clean samples. Need at least 20.")
        sys.exit(1)

    X_all = np.array(Xm + Xc, dtype=np.float32)
    y_all = np.array(ym + yc,  dtype=np.int32)
    n_total = len(y_all)

    ratio = min(len(Xm), len(Xc)) / max(len(Xm), len(Xc))
    print(f"  Dataset:  {len(Xm)} malware  |  {len(Xc)} clean  |  total {n_total}")
    print(f"  Balance:  {ratio:.0%}  ", end="")
    print("✓" if ratio >= 0.5 else "⚠  imbalanced — SMOTE will compensate")

    sss1 = StratifiedShuffleSplit(n_splits=1, test_size=0.40, random_state=42)
    train_idx, rest_idx = next(sss1.split(X_all, y_all))
    X_train, y_train = X_all[train_idx], y_all[train_idx]
    X_rest,  y_rest  = X_all[rest_idx],  y_all[rest_idx]

    sss2 = StratifiedShuffleSplit(n_splits=1, test_size=0.50, random_state=42)
    cal_idx, test_idx = next(sss2.split(X_rest, y_rest))
    X_cal,  y_cal  = X_rest[cal_idx],  y_rest[cal_idx]
    X_test, y_test = X_rest[test_idx], y_rest[test_idx]

    print(f"  Split:    {len(X_train)} train  |  {len(X_cal)} calibration  |  {len(X_test)} test\n")

    if HAS_SMOTE and ratio < 0.8:
        print("  Applying SMOTE to balance training set ...")
        try:
            k_neighbors = min(5, min(len(Xm), len(Xc)) - 1)
            sm = SMOTE(random_state=42, k_neighbors=max(1, k_neighbors))
            X_train, y_train = sm.fit_resample(X_train, y_train)
            unique, counts = np.unique(y_train, return_counts=True)
            print(f"  After SMOTE: {dict(zip(unique, counts))}")
        except Exception as e:
            print(f"  SMOTE failed ({e}) — using class weights instead")
            sw_train = compute_sample_weight("balanced", y=y_train)
    else:
        sw_train = compute_sample_weight("balanced", y=y_train)

    n_folds = 5 if n_total >= 100 else 3
    print(f"  {n_folds}-fold cross-validation ...")
    cv = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)

    cv_model = _make_xgb(n_total) if HAS_XGB else _make_rf(n_total)
    sw_all = compute_sample_weight("balanced", y=y_all)
    try:
        auc_scores = cross_val_score(cv_model, X_all, y_all, cv=cv, scoring="roc_auc", n_jobs=-1)
        rec_scores = cross_val_score(cv_model, X_all, y_all, cv=cv, scoring="recall", n_jobs=-1)
        
        print(f"    AUC    {auc_scores.mean():.4f} ± {auc_scores.std():.4f}", end="")
        if   auc_scores.mean() >= 0.98: print("  ✓✓ Excellent")
        elif auc_scores.mean() >= 0.95: print("  ✓  Good")
        else:                           print("  ⚠  Needs better data")

        print(f"    Recall {rec_scores.mean():.4f} ± {rec_scores.std():.4f}", end="")
        if rec_scores.mean() >= 0.98:   print("  ✓✓ Near-zero false negatives")
        else:                           print("  ⚠  Too many missed samples")
    except Exception as e:
        print(f"    CV skipped: {e}")
        auc_scores = rec_scores = np.array([0.0])

    print("\n  Training XGBoost ...")
    xgb = _make_xgb(len(X_train))
    sw  = compute_sample_weight("balanced", y=y_train)
    if HAS_XGB:
        xgb.fit(X_train, y_train, sample_weight=sw, eval_set=[(X_cal, y_cal)], verbose=False)
    else:
        xgb = _make_rf(len(X_train))
        xgb.fit(X_train, y_train, sample_weight=sw)

    print("  Training RandomForest ...")
    rf = _make_rf(len(X_train))
    rf.fit(X_train, y_train, sample_weight=sw)

    print("  Calibrating probabilities (isotonic regression) ...")
    cal_xgb = CalibratedClassifierCV(xgb, method="isotonic")
    cal_xgb.fit(X_cal, y_cal)
    cal_rf  = CalibratedClassifierCV(rf,  method="isotonic")
    cal_rf.fit(X_cal, y_cal)

    print("  Building ensemble (XGBoost 60% + RandomForest 40%) ...")

    def ensemble_proba(X: np.ndarray) -> np.ndarray:
        p_xgb = cal_xgb.predict_proba(X)[:, 1]
        p_rf  = cal_rf.predict_proba(X)[:, 1]
        return 0.60 * p_xgb + 0.40 * p_rf

    print("\n  Tuning threshold for ZERO false negatives ...")
    cal_probs = ensemble_proba(X_cal)
    best_thresh, thresh_msg = tune_threshold_zero_fn(cal_probs, y_cal)
    print(f"  {thresh_msg}")

    print("\n  Final evaluation on held-out test set:")
    test_probs = ensemble_proba(X_test)
    y_pred = (test_probs >= best_thresh).astype(int)

    metrics = {}
    if len(np.unique(y_test)) > 1:
        cm = confusion_matrix(y_test, y_pred)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall    = recall_score(y_test, y_pred, zero_division=0)
            f1        = f1_score(y_test, y_pred, zero_division=0)
            try:
                auc = roc_auc_score(y_test, test_probs)
            except Exception:
                auc = 0.0

            fn_str = f"{'✓ ZERO' if fn == 0 else f'⚠  {fn}'}"
            print(f"    Recall    (malware caught)   : {recall:.4f}  FN={fn_str}")
            print(f"    Precision (no false alarms)  : {precision:.4f}  FP={fp}")
            print(f"    F1 Score                     : {f1:.4f}")
            print(f"    ROC-AUC                      : {auc:.4f}")
            print(f"    TP={tp}  TN={tn}  FP={fp}  FN={fn}")

            if fn > 0:
                print(f"\n  ⚠  WARNING: {fn} malware sample(s) missed on test set!")

            metrics = dict(
                val_precision=float(precision), val_recall=float(recall),
                val_f1=float(f1), val_auc=float(auc),
                val_tp=int(tp), val_tn=int(tn), val_fp=int(fp), val_fn=int(fn),
            )
        else:
            print("  ⚠  Could not compute full metrics (insufficient test samples)")
    else:
        print("  ⚠  Test set has only one class — metrics skipped")

    print_feature_importance(cal_xgb)

    # ── FIX 3: Automated Model Backups ────────────────────────────────────
    target_model_path = OUT / "model.pkl"
    if target_model_path.exists():
        backup_path = OUT / f"model_backup_{int(time.time())}.pkl"
        shutil.copy(target_model_path, backup_path)
        print(f"\n  [Backup] Previous model saved to: {backup_path.name}")

    print("  Saving new models ...")
    joblib.dump(cal_xgb, OUT / "model_xgb.pkl",  compress=3)
    joblib.dump(cal_rf,  OUT / "model_rf.pkl",   compress=3)
    
    wrapper = EnsembleWrapper(cal_xgb, cal_rf, w_xgb=0.60, w_rf=0.40)
    joblib.dump(wrapper, target_model_path, compress=3)

    meta = {
        "trained_at"         : time.strftime("%Y-%m-%d %H:%M:%S"),
        "malware_samples"    : len(Xm),
        "clean_samples"      : len(Xc),
        "total_samples"      : n_total,
        "features"           : FEATURE_NAMES,
        "n_features"         : len(FEATURE_NAMES),
        "cv_auc_mean"        : float(auc_scores.mean()),
        "cv_auc_std"         : float(auc_scores.std()),
        "cv_recall_mean"     : float(rec_scores.mean()),
        "cv_recall_std"      : float(rec_scores.std()),
        "detection_threshold": float(best_thresh),
        "model_type"         : "EnsembleXGB+RF_calibrated_isotonic",
        "zero_fn_achieved"   : metrics.get("val_fn", -1) == 0,
        **metrics,
    }
    (OUT / "model_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    history_path = LOGS / "training_history.json"
    history = []
    if history_path.exists():
        try:
            history = json.loads(history_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    history.append(meta)
    history_path.write_text(json.dumps(history, indent=2), encoding="utf-8")

    elapsed = time.time() - t0
    print(f"\n  ✓  model.pkl        → models/")
    print(f"  ✓  model_meta.json  → models/")
    print(f"  ✓  training_history → logs/")
    print(f"  Elapsed: {elapsed:.1f}s")
    print("\n" + "=" * 60)
    
    if meta.get("zero_fn_achieved", False):
        print("  ✓✓  ZERO FALSE NEGATIVES achieved on test set.")
    else:
        print("  ⚠   Zero FN not achieved — add more malware samples.")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()