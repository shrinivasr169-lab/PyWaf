from typing import Dict, Any, List
from .utils import shannon_entropy
import os, joblib
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent.parent / "data" / "anomaly_iforest.joblib"

FEATURES = [
    "path_len",
    "query_len",
    "body_len",
    "num_params",
    "special_ratio",
    "entropy_path",
    "entropy_query",
    "entropy_body",
]

def extract_features(sample: Dict[str, Any]) -> List[float]:
    path = sample.get("path","")
    query = sample.get("query","")
    body = sample.get("body","")
    specials = set("""!@#$%^&*()_+-=[]{}/\\|;:'",.<>?`~""")
    special_ratio = (sum(ch in specials for ch in (path+query+body)) / max(1, len(path+query+body)))
    num_params = sample.get("num_params", 0)
    return [
        len(path),
        len(query),
        len(body),
        float(num_params),
        float(special_ratio),
        shannon_entropy(path),
        shannon_entropy(query),
        shannon_entropy(body),
    ]

class AnomalyDetector:
    def __init__(self, threshold: float = 0.62):
        self.threshold = threshold
        self.model = None
        if MODEL_PATH.exists():
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception:
                self.model = None

    def score(self, feats: List[float]) -> float:
        # If model exists, map raw decision_function to 0..1 anomaly score
        if self.model is not None:
            try:
                # Higher is more normal in IsolationForest; invert to anomaly-like score
                d = float(self.model.decision_function([feats])[0])  # typically [-0.5..+0.5]
                # normalize roughly to [0,1] anomaly; clamp
                s = max(0.0, min(1.0, 0.5 - d))
                return s
            except Exception:
                pass
        # Fallback heuristic
        # Heuristic: heavy specials + long body + high entropy
        _, _, body_len, _, special_ratio, _, _, ent_body = feats
        s = 0.0
        s += min(1.0, special_ratio*2.0)
        s += min(1.0, ent_body/5.0)
        s += 0.5 if body_len > 2000 else 0.0
        return min(1.0, s/2.0)

    def is_anomalous(self, feats: List[float]) -> bool:
        return self.score(feats) >= self.threshold
