import os, asyncio, time, json
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from waf import WAFMiddleware
from waf.logger import LOGS
from waf.proxy import ReverseProxy

app = FastAPI(title="PyWAF")
app.add_middleware(WAFMiddleware, config_path="config.yaml")

templates = Jinja2Templates(directory="ui/templates")
proxy = ReverseProxy()

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/events")
async def events():
    async def event_stream():
        while True:
            data = LOGS.snapshot()
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(1.0)
    return StreamingResponse(event_stream(), media_type="text/event-stream")

# Reverse-proxy catch-all
@app.api_route("/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"])
async def proxy_all(request: Request, path: str):
    body = await request.body()
    # Fast path for dashboard assets - not proxied
    if path.startswith("ui/") or path.startswith("events") or path.startswith("dashboard"):
        return PlainTextResponse("Not Found", status_code=404)

    # Forward to upstream if allowed by WAF (middleware runs before this)
    method = request.method
    query = request.url.query
    # rebuild headers
    headers = {k:v for k,v in request.headers.items()}
    resp = await proxy.forward(method, "/" + path, query, headers, body)

    # Relay response
    raw = resp.content
    out = Response(content=raw, status_code=resp.status_code)
    # copy headers (skip transfer-encoding)
    for k, v in resp.headers.items():
        if k.lower() not in ["content-encoding","transfer-encoding","content-length","connection"]:
            out.headers[k] = v
    return out
