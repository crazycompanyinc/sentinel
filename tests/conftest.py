from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

from sentinel.core.db import SentinelDB


@pytest.fixture()
def db(tmp_path):
    return SentinelDB(tmp_path / "sentinel.db")


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DB", str(tmp_path / "cli.db"))
    return CliRunner()

