# SPDX-License-Identifier: AGPL-3.0-only
"""The live Entra probe takes its lab tenant's domain from its own credential file (#125).

`tests/test_graph_live_probe.py` is collected only where `EXECBOUND_GRAPH_LIVE=1`, so how it
reads that file is checked here, where every run collects it: the file is the one
`EXECBOUND_GRAPH_CREDENTIAL` names and no other, the domain comes from the file's `ENTRA_DOMAIN`
line, a file without one refuses the probe, and the probe's source names no tenant of its own.
"""

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest
from test_graph_live_probe import allowed_upn, lab_domain, lab_settings

PROBE = Path(__file__).parent / "test_graph_live_probe.py"


def credential_file(tmp_path: Path, domain_line: str) -> Path:
    path = tmp_path / "entra-execute.env"
    path.write_text(
        "# The execute registration of the lab tenant.\n"
        "ENTRA_DIRECTORY_ID=00000000-0000-0000-0000-000000000001\n"
        "ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000002\n"
        "ENTRA_CLIENT_SECRET=fixture-execute-secret\n" + domain_line,
        encoding="utf-8",
    )
    return path


def test_the_probe_reads_its_tenant_domain_from_the_credential_file(tmp_path):
    path = credential_file(tmp_path, "ENTRA_DOMAIN = contoso.onmicrosoft.com\n")
    assert lab_domain(lab_settings(path)) == "contoso.onmicrosoft.com"


@pytest.mark.parametrize("domain_line", ["", "ENTRA_DOMAIN=\n", "# ENTRA_DOMAIN=x.example\n"])
def test_a_credential_file_without_a_domain_refuses_the_probe(tmp_path, domain_line):
    with pytest.raises(LookupError, match="ENTRA_DOMAIN"):
        lab_domain(lab_settings(credential_file(tmp_path, domain_line)))


def test_the_probe_fails_its_setup_on_a_credential_file_without_a_domain(tmp_path):
    with pytest.raises(pytest.fail.Exception, match="ENTRA_DOMAIN"):
        allowed_upn(credential_file(tmp_path, ""))


def test_the_probe_names_no_tenant_domain_of_its_own():
    source = PROBE.read_text(encoding="utf-8")
    assert re.search(r"\.onmicrosoft\.com", source) is None


def load_probe(monkeypatch, named: str | None) -> ModuleType:
    """The probe's module as a run with `EXECBOUND_GRAPH_CREDENTIAL` set to `named` loads it."""
    if named is None:
        monkeypatch.delenv("EXECBOUND_GRAPH_CREDENTIAL", raising=False)
    else:
        monkeypatch.setenv("EXECBOUND_GRAPH_CREDENTIAL", named)
    spec = importlib.util.spec_from_file_location("graph_live_probe_as_loaded", PROBE)
    assert spec is not None and spec.loader is not None
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    return probe


@pytest.mark.parametrize("named", [None, ""])
def test_without_the_variable_the_probe_reads_no_file_and_skips(monkeypatch, tmp_path, named):
    """No default path: a credential file where an old default pointed is not read."""
    (tmp_path / "local-data").mkdir()
    credential_file(tmp_path / "local-data", "ENTRA_DOMAIN=contoso.onmicrosoft.com\n")
    monkeypatch.chdir(tmp_path)
    probe = load_probe(monkeypatch, named)
    assert probe.CREDENTIAL is None
    assert probe.pytestmark.args == (True,)


def test_the_probe_reads_the_credential_file_the_variable_names(monkeypatch, tmp_path):
    path = credential_file(tmp_path, "ENTRA_DOMAIN=contoso.onmicrosoft.com\n")
    probe = load_probe(monkeypatch, str(path))
    assert probe.CREDENTIAL == path
    assert probe.pytestmark.args == (False,)
    assert probe.allowed_upn() == "disposable.target@contoso.onmicrosoft.com"
