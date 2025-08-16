# PyWAF – AI‑powered Python Web Application Firewall

**Features (MVP)**  
- 🚫 Block known web attacks (regex signatures for SQLi/XSS/RCE/LFI/Traversal)  
- 🤖 AI-powered anomaly scoring (IsolationForest over request features)  
- 🛡️ Real-time request analysis (middleware + streaming events)  
- ✨ Modern, responsive UI (Tailwind + Chart.js dashboard)  
- 📊 Interactive security insights (live feed + filters)  
- 🚀 Fast response time (async FastAPI reverse-proxy with httpx)

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# (Optional) Train a small anomaly model
python scripts/train_model.py

# Configure upstream target (the app you want to protect)
export PYWAF_UPSTREAM="http://127.0.0.1:9000"            # Windows (Powershell): $env:PYWAF_UPSTREAM="http://127.0.0.1:9000"

# Run the firewall
uvicorn app:app --host 0.0.0.0 --port 8080 --reload
```

Visit:
- Firewalled reverse-proxy: `http://localhost:8080/` → forwards to your upstream
- Dashboard: `http://localhost:8080/dashboard`
- Live events (SSE): `http://localhost:8080/events`

## How it works (high level)
- **ASGI Middleware** inspects each request (path, query, headers, small body sample).  
- **Signature Engine** checks known bad patterns (SQL meta-chars, JS contexts, traversal, etc.).  
- **Detector** extracts numeric features (length, entropy, parameter count, special-char ratio) and scores with **IsolationForest** (fallback: heuristics).  
- **Decision**: block with 403 (and log) if `signature_match` or `anomaly_score` exceeds threshold or IP is blocklisted.  
- **Reverse Proxy**: if allowed, request is proxied to your `PYWAF_UPSTREAM` using async `httpx`.  
- **Realtime**: events streamed via SSE; UI subscribes and renders charts in the dashboard.

## Hardening / Next Steps
- Swap regexes with an OWASP CRS mapping.
- Persist logs to SQLite/ClickHouse; add filters and time-range queries.
- Add per-route/risk-based thresholds; country/IP reputation and rate limiting via Redis.
- Add WebSocket tap for packet-like telemetry.
- Train model with your own traffic and deploy with proper versioning.
- Containerize and add Nginx in front for TLS + buffering.

## Disclaimer
This is an educational starter. Validate thoroughly before production.
