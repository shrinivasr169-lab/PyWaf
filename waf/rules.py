import re
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class Signature:
    name: str
    pattern: re.Pattern
    severity: int

def _rx(p): 
    return re.compile(p, re.IGNORECASE | re.MULTILINE)

# Minimal, demonstrative signatures. Expand to match OWASP CRS ideas.
SIGNATURES: List[Signature] = [
    Signature("SQLi: tautology", _rx(r"(?:'|\")\s*or\s+(?:'1'='1|1=1)"), 8),
    Signature("SQLi: UNION select", _rx(r"\bunion\b\s+select\b"), 7),
    Signature("XSS: script tag", _rx(r"<\s*script[^>]*>"), 8),
    Signature("XSS: event handlers", _rx(r"on(?:error|load|mouseover)\s*="), 6),
    Signature("Traversal", _rx(r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\"), 7),
    Signature("Command Injection", _rx(r"[;&|`]\s*(?:cat|ls|id|whoami|ping|curl|wget)\b"), 9),
    Signature("Java Deserialization", _rx(r"rO0AB"), 9),
    Signature("LFI/RFI", _rx(r"(?:/etc/passwd|file://|php://input)"), 6),
]

def find_matches(payload: str) -> List[Tuple[str,int]]:
    hits = []
    for s in SIGNATURES:
        if s.pattern.search(payload):
            hits.append((s.name, s.severity))
    return hits
