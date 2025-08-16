import random, os
import numpy as np
from sklearn.ensemble import IsolationForest
from joblib import dump
from pathlib import Path

from waf.detector import FEATURES
from waf.utils import shannon_entropy

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = DATA_DIR / "anomaly_iforest.joblib"

def synth_normal(n=1000):
    rows = []
    for _ in range(n):
        path_len = random.randint(1, 40)
        query_len = random.randint(0, 120)
        body_len = random.randint(0, 1024)
        num_params = random.randint(0, 6)
        total_len = path_len+query_len+body_len
        specials = max(0.0, random.random()*0.08)
        entropy_path = random.uniform(1.0, 3.5)
        entropy_query = random.uniform(1.0, 4.0)
        entropy_body = random.uniform(1.0, 4.0)
        rows.append([path_len,query_len,body_len,num_params,specials,entropy_path,entropy_query,entropy_body])
    return np.array(rows, dtype=float)

def synth_attack(n=250):
    rows = []
    for _ in range(n):
        path_len = random.randint(20, 120)
        query_len = random.randint(40, 500)
        body_len = random.randint(512, 4096)
        num_params = random.randint(2, 20)
        specials = random.uniform(0.15, 0.6)
        entropy_path = random.uniform(2.0, 5.0)
        entropy_query = random.uniform(2.5, 5.5)
        entropy_body = random.uniform(3.0, 6.0)
        rows.append([path_len,query_len,body_len,num_params,specials,entropy_path,entropy_query,entropy_body])
    return np.array(rows, dtype=float)

if __name__ == "__main__":
    X_norm = synth_normal()
    X_bad = synth_attack()
    X = np.vstack([X_norm, X_bad])
    model = IsolationForest(n_estimators=200, contamination=0.18, random_state=42)
    model.fit(X)
    dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")
