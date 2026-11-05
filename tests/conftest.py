import pytest


@pytest.fixture(autouse=True)
def no_vt_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)