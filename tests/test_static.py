import re
from collections import Counter
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "static"


def test_html_ids_are_unique():
    # a duplicate id made the change-password form bind to the wrong element (found by the browser run, not by unit tests)
    ids = re.findall(r'\sid="([^"]+)"', (STATIC / "index.html").read_text(encoding="utf-8"))
    assert [i for i, n in Counter(ids).items() if n > 1] == []


def test_every_dollar_id_used_by_the_script_exists_in_the_page():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    ids = set(re.findall(r'\sid="([^"]+)"', html))
    used = set(re.findall(r'\$\("([A-Za-z][\w-]*)"\)', (STATIC / "app.js").read_text(encoding="utf-8")))
    assert sorted(used - ids) == []
