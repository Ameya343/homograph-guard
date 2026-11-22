"""The browser extension re-implements the analysis in JavaScript. tests/vectors/analysis.json is the
contract between the two: the Python results are pinned here, and extension/tests/analyzer.test.mjs
checks that the JavaScript port produces the same verdict, score and findings."""

import json
from pathlib import Path

import pytest

pytest.importorskip("publicsuffixlist")  # the vectors are computed with the full Public Suffix List

VECTORS = json.loads((Path(__file__).parent / "vectors" / "analysis.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("v", VECTORS, ids=[v["input"][:60] for v in VECTORS])
def test_python_matches_pinned_vectors(offline, v):
    rep = offline.analyze(v["input"], v["context"])
    got = {"verdict": rep["verdict"], "score": rep["score"], "codes": sorted(f["code"] for f in rep["findings"]),
           "host_ascii": (rep.get("url") or {}).get("host_ascii")}
    want = {k: v[k] for k in ("verdict", "score", "codes", "host_ascii")}
    assert got == want, "run: python scripts/build_extension_data.py (and check the JS tests)"


def test_extension_data_is_up_to_date():
    import re
    import subprocess
    import sys
    from importlib.metadata import version

    root = Path(__file__).resolve().parent.parent
    lock = (root / "requirements.lock").read_text(encoding="utf-8")
    pinned = re.search(r"^publicsuffixlist==(\S+)", lock, re.M).group(1)
    if version("publicsuffixlist") != pinned:  # data.js embeds the suffix list, so it must be the pinned one
        pytest.skip(f"data.js is built with the pinned Public Suffix List {pinned}, this environment has "
                    f"{version('publicsuffixlist')}")
    proc = subprocess.run([sys.executable, str(root / "scripts" / "build_extension_data.py"), "--check"],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
