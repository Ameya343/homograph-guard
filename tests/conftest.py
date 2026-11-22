import os
import sys
import tempfile
from pathlib import Path

import pytest

# Never touch the real data directory (threat database, lists, settings) or a real policy file.
os.environ["HGUARD_HOME"] = tempfile.mkdtemp(prefix="hg-test-home-")
os.environ["HGUARD_POLICY"] = os.path.join(os.environ["HGUARD_HOME"], "no-policy.json")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from homograph_guard.analyzer import Analyzer  # noqa: E402
from homograph_guard.brands import BrandIndex, default_domains  # noqa: E402
from homograph_guard.unicode_tools import ConfusableMap  # noqa: E402


@pytest.fixture(scope="session")
def cmap():
    return ConfusableMap.load()


@pytest.fixture(scope="session")
def brands(cmap):
    return BrandIndex(default_domains(), cmap)


@pytest.fixture(scope="session")
def offline(brands, cmap):
    return Analyzer(brands, cmap)


@pytest.fixture(scope="session")
def lab(tmp_path_factory):
    from dnslab import Lab

    lab = Lab(tmp_path_factory.mktemp("pki")).start()
    yield lab
    lab.stop()


def codes(report):
    return {f["code"] for f in report["findings"]}
