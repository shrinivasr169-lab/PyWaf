from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.datastructures import Headers
from typing import Callable, Awaitable
import time, yaml, io, re, json
from .rules import find_matches
from .detector import AnomalyDetector, extract_features
from .logger import LOGS
from .utils import RateLimiter

class WAFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config_path: str = "config.yaml"):
        super().__init__(app)
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        self.block_on_signature = bool(cfg.get("block_on_signature", True))
        self.block_on_model = bool(cfg.get("block_on_model", True))
        self.max_body_sample = int(cfg.get("max_body_sample", 4096))
        self.detector = AnomalyDetector(threshold=float(cfg.get("anomaly_threshold", 0.62)))
        self.ratelimiter = RateLimiter(per_minute=int(cfg.get("rate_limit_per_minute", 120)))

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]):
        t0 = time.time()
        client_ip = request.client.host if request.client else "unknown"
        path = request.url.path
        query = request.url.query or ""
        method = request.method

        # Rate limit simple
        if not self.ratelimiter.allow(client_ip):
            LOGS.add({"action":"rate_limited","ip":client_ip,"path":path,"method":method})
            return JSONResponse({"detail":"Rate limit exceeded"}, status_code=429)

        # Sample body without consuming downstream
        body_bytes = await request.body()
        sample = body_bytes[: self.max_body_sample]
        # Recreate request stream for downstream
        request._body = body_bytes  # NOTE: Starlette trick for reusing body

        # Build payload string for signatures
        payload = " ".join([path, query, sample.decode(errors="ignore")])
        sig_hits = find_matches(payload)

        # Features for model
        num_params = 0
        if query:
            num_params = sum(1 for _ in query.split("&") if _)
        feats = extract_features({
            "path": path,
            "query": query,
            "body": sample.decode(errors="ignore"),
            "num_params": num_params
        })
        anomaly_score = self.detector.score(feats)
        is_anom = anomaly_score >= self.detector.threshold

        blocked = False
        reason = None
        if self.block_on_signature and sig_hits:
            blocked = True
            reason = f"signature: {', '.join(n for n,_ in sig_hits)}"
        if self.block_on_model and is_anom:
            blocked = True
            reason = (reason + "; " if reason else "") + f"anomaly_score={anomaly_score:.2f}"

        if blocked:
            latency_ms = int((time.time()-t0)*1000)
            LOGS.add({
                "action":"blocked",
                "ip": client_ip,
                "path": path,
                "method": method,
                "reason": reason,
                "anomaly": anomaly_score,
                "signatures": [n for n,_ in sig_hits],
                "latency_ms": latency_ms,
            })
            return JSONResponse({"detail":"Request blocked by WAF", "reason":reason}, status_code=403)

        # Otherwise pass to app
        resp = await call_next(request)
        latency_ms = int((time.time()-t0)*1000)
        LOGS.add({
            "action":"allowed",
            "ip": client_ip,
            "path": path,
            "method": method,
            "anomaly": anomaly_score,
            "signatures": [n for n,_ in sig_hits],
            "latency_ms": latency_ms,
        })
        return resp
