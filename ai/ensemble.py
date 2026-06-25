"""
ensemble.py — Ensemble wrapper for the trained AV model.
Must be a standalone module (not inside train.py) so joblib
can deserialize model.pkl correctly when loaded from bridge.py or app.py.

Enterprise Upgrades:
- Inherits BaseEstimator and ClassifierMixin for full sklearn API compliance.
- Explicitly defines classes_ array.
- Validates 2D input dimensions.
"""
from __future__ import annotations
import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.utils.validation import check_array
from extractor import FEATURE_NAMES

class EnsembleWrapper(BaseEstimator, ClassifierMixin):
    """
    Soft-vote ensemble of calibrated XGBoost + RandomForest.
    Fully sklearn-compatible for seamless pipeline integration and joblib loading.
    """
    def __init__(self, cal_xgb, cal_rf, w_xgb: float = 0.60, w_rf: float = 0.40):
        self._xgb         = cal_xgb
        self._rf          = cal_rf
        self.w_xgb        = w_xgb
        self.w_rf         = w_rf
        
        # Bridge.py uses this to detect stale models
        self.n_features_in_ = len(FEATURE_NAMES)
        
        # Required for full sklearn ClassifierMixin compliance
        self.classes_ = np.array([0, 1])

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        # Validate that X is a 2D array and cast to float32 for speed
        X_val = check_array(X, accept_sparse=False, dtype=np.float32)
        
        p_xgb    = self._xgb.predict_proba(X_val)[:, 1]
        p_rf     = self._rf.predict_proba(X_val)[:, 1]
        
        # Compute the weighted average for the positive class (Malicious)
        blended  = self.w_xgb * p_xgb + self.w_rf * p_rf
        
        # Return a standard 2D probability matrix [P(Clean), P(Malicious)]
        return np.column_stack([1 - blended, blended])

    def predict(self, X: np.ndarray) -> np.ndarray:
        # Default threshold of 0.5 (bridge.py handles dynamic thresholding)
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)