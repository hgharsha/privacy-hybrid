"""Documents that cite a threat (T<n>) must cite one that exists in the threat model."""
import re
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs"


def test_every_cited_threat_exists():
    rows = set(re.findall(r"^\| (T\d+) \|", (DOCS / "THREAT-MODEL.md").read_text(), re.M))
    assert rows
    for f in DOCS.glob("*.md"):
        cited = set(re.findall(r"\bT\d+\b", f.read_text()))
        assert cited <= rows, f"{f.name} cites {sorted(cited - rows)}"
