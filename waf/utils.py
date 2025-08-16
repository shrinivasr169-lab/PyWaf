import re, math
from collections import defaultdict
from typing import Dict
from time import time

class RateLimiter:
    def __init__(self, per_minute: int = 120):
        self.per_minute = per_minute
        self.buckets: Dict[str, list] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time()
        window_start = now - 60
        buf = self.buckets[key]
        # prune
        while buf and buf[0] < window_start:
            buf.pop(0)
        if len(buf) >= self.per_minute:
            return False
        buf.append(now)
        return True

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    probs = [c/len(s) for c in freq.values()]
    return -sum(p*log2(p) for p in probs)
