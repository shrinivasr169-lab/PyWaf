import time
from collections import deque, defaultdict
from typing import Dict, Any

class InMemoryLogStore:
    """Tiny log store for demo. Replace with SQLite/ClickHouse in production."""
    def __init__(self, maxlen: int = 5000):
        self.events = deque(maxlen=maxlen)
        self.counts = defaultdict(int)
        self.latencies = deque(maxlen=maxlen)

    def add(self, event: Dict[str, Any]):
        event['ts'] = time.time()
        self.events.appendleft(event)
        self.counts[event.get('action','unknown')] += 1
        if 'latency_ms' in event:
            self.latencies.append(event['latency_ms'])

    def snapshot(self):
        return {
            "events": list(self.events)[:200],
            "counts": dict(self.counts),
            "avg_latency_ms": (sum(self.latencies)/len(self.latencies)) if self.latencies else 0.0,
        }

LOGS = InMemoryLogStore()
