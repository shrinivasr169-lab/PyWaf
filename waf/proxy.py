import os
import httpx
from typing import Dict, Any, Optional

UPSTREAM = os.getenv("PYWAF_UPSTREAM", "http://httpbin.org")  # demo

class ReverseProxy:
    def __init__(self):
        self.client = httpx.AsyncClient(follow_redirects=True, timeout=10.0)

    async def forward(self, method: str, path: str, query: str, headers: Dict[str, str], body: Optional[bytes]):
        url = f"{UPSTREAM}{path}"
        if query:
            url = f"{url}?{query}"
        # Strip hop-by-hop headers
        hop = {"connection","keep-alive","proxy-authenticate","proxy-authorization","te","trailers","transfer-encoding","upgrade"}
        fwd_headers = {k:v for k,v in headers.items() if k.lower() not in hop}
        resp = await self.client.request(method, url, headers=fwd_headers, content=body)
        return resp
