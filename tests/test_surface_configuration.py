# SPDX-License-Identifier: AGPL-3.0-only
import json
from copy import deepcopy
from dataclasses import replace
from uuid import UUID, uuid4

import pytest

from execbound.db import Database
from execbound.provider.connector import ConnectionConfig, MockConnector
from execbound.runtime import Runtime
from execbound.surfaces.configuration import load_runtime, read_configuration, reload_keys

# The example block `docs/ARCADE.md` gives: one governed tool, one ungoverned toolkit, and the
# deadline the extension answers within. `tests/test_arcade.py` builds its files from this.
ARCADE = {
    "deadline_seconds": 4.0,
    "tools": [
        {
            "toolkit": "endpoint_mock",
            "name": "ContainDevice",
            "versions": ["1.0"],
            "operation_ref": "endpoint.isolate",
            "target": {"kind": "provider_id", "input": "device_id"},
            "inputs": ["device_id"],
            "arguments": {},
            "expect": {"destructive": True, "read_only": False},
        }
    ],
    "ungoverned_toolkits": ["gmail"],
}


@pytest.fixture
def config():
    return {
        "origin": "http://127.0.0.1:8000",
        "active_key_id": "state-v1",
        "continuation_keys": {"state-v1": "21" * 32},
        "connectors": [
            {
                "tenant_id": "00000000-0000-0000-0000-000000000001",
                "account_id": "00000000-0000-0000-0000-000000000002",
                "origin": "http://127.0.0.1:8001",
                "dispatch_token": "dispatch-test" * 3,
                "control_token": "control-test" * 3,
                "evidence_keys": {"proof": "31" * 32},
            }
        ],
    }


def load(tmp_path, value):
    """The runtime and human surface one private file produces, closed before the return.

    The origin, the approval URL and each connector's provider are asserted here because
    every caller wants them of whatever file it wrote; a caller that cares about one of
    them in particular varies the file and reads the pair back.
    """
    path = tmp_path / "private.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    db = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    try:
        runtime, human = load_runtime(path, db)
        assert human.origin == value["origin"]
        assert runtime.approval_url == value["origin"] + "/approvals"
        for connector in runtime.connectors.values():
            assert connector.config.provider == value["connectors"][0].get(
                "provider", "mock_crowdstrike"
            )
            connector.close()
        return runtime, human
    finally:
        db.close()


def test_config_is_explicit_and_requires_no_network(tmp_path, config):
    assert not load(tmp_path, config)[1].secure
    config["origin"] = "https://review.example.test"
    _, human = load(tmp_path, config)
    assert human.secure and human.cookie("session") == "__Host-eb_session"


def test_identity_config_selects_the_separate_provider_kind(tmp_path, config):
    config["connectors"][0]["provider"] = "mock_entra"
    load(tmp_path, config)
    config["connectors"][0]["provider"] = "unregistered_provider"
    with pytest.raises(ValueError, match="^Invalid runtime configuration$"):
        load(tmp_path, config)


@pytest.mark.parametrize(
    "reuse",
    [
        "none",
        "dispatch_dispatch",
        "dispatch_control",
        "control_dispatch",
        "control_control",
        "evidence",
    ],
)
def test_provider_families_require_independent_authentication_and_evidence(reuse):
    tenant = uuid4()
    endpoint = ConnectionConfig(
        tenant,
        uuid4(),
        "http://127.0.0.1:1",
        "endpoint-dispatch" * 3,
        "endpoint-control" * 3,
        {"endpoint": b"e" * 32},
    )
    identity = ConnectionConfig(
        tenant,
        uuid4(),
        "http://127.0.0.1:2",
        "identity-dispatch" * 3,
        "identity-control" * 3,
        {"identity": b"i" * 32},
        provider="mock_entra",
    )
    if reuse == "evidence":
        identity = replace(identity, evidence_keys={"different-key-id": b"e" * 32})
    elif reuse != "none":
        source, destination = reuse.split("_")
        identity = replace(
            identity, **{destination + "_token": getattr(endpoint, source + "_token")}
        )
    connectors = [MockConnector(endpoint), MockConnector(identity)]
    db = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    try:
        if reuse == "none":
            assert len(Runtime(db, connectors).connectors) == 2
        else:
            with pytest.raises(ValueError, match="independent"):
                Runtime(db, connectors)
    finally:
        for connector in connectors:
            connector.close()
        db.close()


@pytest.mark.parametrize(
    "failure",
    [
        "shared_key",
        "unknown",
        "duplicate_account",
        "public_cleartext",
        "userinfo",
        "origin_path",
        "short_key",
        "bad_id",
        "secret_url",
    ],
)
def test_invalid_config_fails_without_secret_diagnostics(tmp_path, config, failure):
    connector = config["connectors"][0]
    if failure == "shared_key":
        config["continuation_keys"]["state-v1"] = "31" * 32
    if failure == "unknown":
        config["secret"] = "do-not-print"
    if failure == "duplicate_account":
        config["connectors"].append(connector)
    if failure == "public_cleartext":
        config["origin"] = "http://review.example.test"
    if failure == "userinfo":
        config["origin"] = "https://do-not-print@review.example.test"
    if failure == "origin_path":
        config["origin"] += "/path"
    if failure == "short_key":
        config["continuation_keys"]["state-v1"] = "11"
    if failure == "bad_id":
        connector["tenant_id"] = "do-not-print"
    if failure == "secret_url":
        connector["origin"] += "/?secret=do-not-print"
    with pytest.raises(ValueError, match="^Invalid runtime configuration$") as exc:
        load(tmp_path, config)
    assert exc.value.__context__ is None


def test_precondition_classes_are_declared_in_the_private_configuration(tmp_path, config):
    """An operator can say what a vendor does with a frozen expected version, or nothing.

    Without this block every deployed runtime holds no declaration at all, so every
    checkpoint grant answers UNAVAILABLE and carries no version whatever the vendor
    supports. The file is the only production construction path, so this is the surface
    that makes the class reachable outside a Python-constructed Runtime.
    """
    assert load(tmp_path, config)[0].preconditions.declared("mock_crowdstrike", "contain") == (
        "UNAVAILABLE"
    )
    config["preconditions"] = [
        {
            "provider": "mock_crowdstrike",
            "provider_operation": "contain",
            "precondition_class": "ENFORCED_BY_PROVIDER",
        },
        {
            "provider": "mock_entra",
            "provider_operation": "disable",
            "precondition_class": "ASSERTED_BY_EXECUTOR",
        },
    ]
    declared = load(tmp_path, config)[0].preconditions
    assert declared.declared("mock_crowdstrike", "contain") == "ENFORCED_BY_PROVIDER"
    assert declared.declared("mock_entra", "disable") == "ASSERTED_BY_EXECUTOR"
    # A binding no entry names is undeclared, and an undeclared binding promises nothing.
    assert declared.declared("mock_crowdstrike", "lift_containment") == "UNAVAILABLE"
    # The native path's own class is declarable here too: a deployment whose vendor offers
    # no conditional write says so once, in configuration, rather than per dispatch.
    config["preconditions"].append(
        {
            "provider": "mock_entra",
            "provider_operation": "enable",
            "precondition_class": "CHECKED_BY_CONNECTOR",
        }
    )
    assert load(tmp_path, config)[0].preconditions.declared("mock_entra", "enable") == (
        "CHECKED_BY_CONNECTOR"
    )


@pytest.mark.parametrize(
    "failure",
    [
        "unknown_class",
        "unbound_binding",
        "unknown_provider",
        "duplicate_binding",
        "unknown_field",
        "missing_class",
    ],
)
def test_invalid_precondition_declarations_are_refused_at_load(tmp_path, config, failure):
    """Validated where it is read, so nothing undeclarable reaches a grant.

    A declaration naming a binding this deployment's catalog does not bind is refused by
    the Runtime, which is the one place that holds the catalog; the file's own shape and a
    binding declared twice are refused here. Both arrive as the same opaque failure.
    """
    entry = {
        "provider": "mock_crowdstrike",
        "provider_operation": "contain",
        "precondition_class": "ENFORCED_BY_PROVIDER",
    }
    config["preconditions"] = [entry]
    if failure == "unknown_class":
        entry["precondition_class"] = "ENFORCED"
    if failure == "unbound_binding":
        entry["provider_operation"] = "quarantine"
    if failure == "unknown_provider":
        entry["provider"] = "Do-Not-Print"
    if failure == "duplicate_binding":
        config["preconditions"] = [entry, dict(entry, precondition_class="UNAVAILABLE")]
    if failure == "unknown_field":
        entry["expected_version"] = "resource-v1"
    if failure == "missing_class":
        del entry["precondition_class"]
    with pytest.raises(ValueError, match="^Invalid runtime configuration$") as exc:
        load(tmp_path, config)
    assert exc.value.__context__ is None


def test_a_reload_refuses_a_changed_precondition_declaration(tmp_path, config):
    """Only the key rings rotate at runtime; a class change needs a restart, not silence.

    Without the declarations in the reload shape, a file that changed one would rotate the
    keys, keep the new file as the baseline and leave the running runtime on the old
    class, so the operator would believe a guarantee was in force that nothing read.
    """
    config["preconditions"] = [
        {
            "provider": "mock_crowdstrike",
            "provider_operation": "contain",
            "precondition_class": "ENFORCED_BY_PROVIDER",
        }
    ]
    path = tmp_path / "private.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    db = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    try:
        runtime, human = load_runtime(path, db)
        baseline = read_configuration(path)
        config["continuation_keys"]["state-v2"] = "41" * 32
        config["active_key_id"] = "state-v2"
        config["preconditions"][0]["precondition_class"] = "ASSERTED_BY_EXECUTOR"
        path.write_text(json.dumps(config), encoding="utf-8")
        reload = reload_keys(path, runtime, human, baseline)
        assert (reload.state, reload.code, reload.rotated) == (
            "refused",
            "CONFIGURATION_CHANGED",
            False,
        )
        assert runtime.keys is not None and runtime.keys.active_key_id == "state-v1"
        assert runtime.preconditions.declared("mock_crowdstrike", "contain") == (
            "ENFORCED_BY_PROVIDER"
        )
    finally:
        for connector in runtime.connectors.values():
            connector.close()
        db.close()


def test_request_limits_are_read_from_the_private_configuration(tmp_path, config):
    config["limits"] = {"agent_requests": 5, "login_attempts": 3, "token_requests": 7}
    path = tmp_path / "limits.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    db = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    try:
        runtime, _ = load_runtime(path, db)
        try:
            assert runtime.limiter.limits.agent_requests == 5
            assert runtime.limiter.limits.login_attempts == 3
            assert runtime.limiter.limits.client_requests == 1000
            assert runtime.limiter.limits.policy("token") == (7, 60)
        finally:
            for connector in runtime.connectors.values():
                connector.close()
        for invalid in (
            {"agent_requests": 0},
            {"login_window_seconds": 3601},
            {"token_window_seconds": 0},
            {"unknown": 1},
        ):
            config["limits"] = invalid
            path.write_text(json.dumps(config), encoding="utf-8")
            with pytest.raises(ValueError):
                load_runtime(path, db)
    finally:
        db.close()


def test_the_arcade_deadline_is_required_with_no_default(tmp_path, config):
    """A number the deployment could not defend is worse than a file it must fill in.

    The extension's deadline decides when a hook gives up on the kernel and leaves whatever
    admission committed as retained uncertainty, and it has to be set against a measurement
    of the granting path in the deployment that runs it. A default would be inherited
    silently from a measurement of something else, so the block that omits it is refused
    here, in the same opaque answer every invalid file gets.
    """
    config["arcade"] = deepcopy(ARCADE)
    assert load(tmp_path, config)[0] is not None
    del config["arcade"]["deadline_seconds"]
    with pytest.raises(ValueError, match="^Invalid runtime configuration$") as exc:
        load(tmp_path, config)
    assert exc.value.__context__ is None


def test_only_an_arcade_deployment_may_declare_no_connector(tmp_path, config):
    """The minimum of one connector relaxes for the deployment that dispatches nothing.

    An Arcade deployment executes through the control point and holds no connector account,
    so it has none to declare. A file with neither is still refused: without this the
    minimum would be gone for every deployment, and a gateway whose connectors were left
    out would load and answer every dispatch with an unresolvable account instead of
    refusing at startup.
    """
    config["connectors"] = []
    with pytest.raises(ValueError, match="^Invalid runtime configuration$") as exc:
        load(tmp_path, config)
    assert exc.value.__context__ is None
    config["arcade"] = deepcopy(ARCADE)
    assert not load(tmp_path, config)[0].connectors


def test_one_file_configures_both_connector_families_selected_by_account(tmp_path, config):
    """A mock and a Graph connection in one deployment, each reached by its own account.

    Which provider serves a request follows from the account, so the two families coexist
    rather than replacing one another. The shapes stay apart in the file because a Graph
    connection has no origin and no bearer tokens.
    """
    graph_account = "00000000-0000-0000-0000-000000000003"
    config["preconditions"] = [
        {
            "provider": "graph",
            "provider_operation": "disable",
            "precondition_class": "CHECKED_BY_CONNECTOR",
        }
    ]
    config["graph_connectors"] = [
        {
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "account_id": graph_account,
            "directory": "00000000-0000-0000-0000-0000000000aa",
            "client_id": "00000000-0000-0000-0000-0000000000bb",
            "client_secret": "graph-client-secret-value",
            "signing_key_id": "connector-v1",
            "evidence_keys": {"connector-v1": "41" * 32},
        }
    ]
    path = tmp_path / "private.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    db = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    try:
        runtime, _ = load_runtime(path, db)
        try:
            providers = {
                account: connector.config.provider
                for (_, account), connector in runtime.connectors.items()
            }
            assert set(providers.values()) == {"mock_crowdstrike", "graph"}
            assert providers[UUID(graph_account)] == "graph"
        finally:
            for connector in runtime.connectors.values():
                connector.close()
    finally:
        db.close()


def test_a_graph_connection_may_not_share_a_secret_with_another_family(tmp_path, config):
    """The independence rule reaches a credential that is not a pair of bearer tokens.

    It reads each connection's own `secrets`, so configuring the Graph client secret as a
    mock's bearer token is refused rather than silently allowed because the rule only knew
    how to read two named fields.
    """
    shared = config["connectors"][0]["dispatch_token"]
    config["preconditions"] = [
        {
            "provider": "graph",
            "provider_operation": "disable",
            "precondition_class": "CHECKED_BY_CONNECTOR",
        }
    ]
    config["graph_connectors"] = [
        {
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "account_id": "00000000-0000-0000-0000-000000000003",
            "directory": "00000000-0000-0000-0000-0000000000aa",
            "client_id": "00000000-0000-0000-0000-0000000000bb",
            "client_secret": shared,
            "signing_key_id": "connector-v1",
            "evidence_keys": {"connector-v1": "41" * 32},
        }
    ]
    path = tmp_path / "private.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    db = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    try:
        with pytest.raises(ValueError):
            load_runtime(path, db)
    finally:
        db.close()


def test_a_graph_connection_that_does_not_declare_what_it_proves_is_refused(tmp_path, config):
    """Refused before a write, because after one there is no good answer left.

    The connector always measures a window and migration `0032` admits one only beside
    CHECKED_BY_CONNECTOR, so a file that declares anything else, or declares nothing and
    takes the UNAVAILABLE default, would disable the user and then fail to settle it.
    """
    config["graph_connectors"] = [
        {
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "account_id": "00000000-0000-0000-0000-000000000003",
            "directory": "00000000-0000-0000-0000-0000000000aa",
            "client_id": "00000000-0000-0000-0000-0000000000bb",
            "client_secret": "graph-client-secret-value",
            "signing_key_id": "connector-v1",
            "evidence_keys": {"connector-v1": "41" * 32},
        }
    ]
    path = tmp_path / "private.json"
    for declaration in (
        [],
        [
            {
                "provider": "graph",
                "provider_operation": "disable",
                "precondition_class": "ENFORCED_BY_PROVIDER",
            }
        ],
    ):
        config["preconditions"] = declaration
        path.write_text(json.dumps(config), encoding="utf-8")
        db = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
        try:
            with pytest.raises(ValueError):
                load_runtime(path, db)
        finally:
            db.close()


def test_the_assistant_block_is_optional_and_makes_the_feature_exist(tmp_path, config):
    """Absent, the assistant does not exist; present, its configuration rides on the
    runtime and the human surface knows the routes may be registered (#330)."""
    runtime, human = load(tmp_path, config)
    assert runtime.assistant is None and human.assistant_enabled is False
    block = {
        "api_key": "sk-test-" + "a" * 24,
        "model": "claude-opus-5",
        "tenant_daily_tokens": 5000,
        "person_hourly_turns": 3,
        "effort": "medium",
    }
    runtime, human = load(tmp_path, config | {"assistant": block})
    assert human.assistant_enabled is True
    assistant = runtime.assistant
    assert assistant is not None
    assert (assistant.model, assistant.effort) == ("claude-opus-5", "medium")
    assert (assistant.tenant_daily_tokens, assistant.person_hourly_turns) == (5000, 3)
    assert assistant.base_url == "https://api.anthropic.com"
    assert "sk-test" not in repr(assistant) and "sk-test" not in repr(runtime)
    runtime, _ = load(tmp_path, config | {"assistant": {"api_key": "k" * 20}})
    assert runtime.assistant is not None and runtime.assistant.model == "claude-sonnet-5"


@pytest.mark.parametrize(
    "block",
    [
        {},
        {"api_key": "k" * 20, "effort": "max"},
        {"api_key": "k" * 20, "tenant_daily_tokens": 10},
        {"api_key": "k" * 20, "base_url": "http://model.example"},
        {"api_key": "k" * 20, "extra": True},
    ],
)
def test_an_assistant_block_it_cannot_run_with_is_refused_without_diagnostics(
    tmp_path, config, block
):
    with pytest.raises(ValueError) as refused:
        load(tmp_path, config | {"assistant": block})
    assert "k" * 20 not in str(refused.value)


def collector_block(tmp_path):
    """A collector public key as `collector-keygen` writes it, and its private file's value."""
    from execbound.monitoring import sealing

    directory = tmp_path / "collector"
    sealing.generate(directory)
    public = json.loads((directory / sealing.PUBLIC_FILE).read_text(encoding="utf-8"))
    private = json.loads((directory / sealing.PRIVATE_FILE).read_text(encoding="utf-8"))
    return public, private["private_key"]


def test_mc2_the_scout_block_is_optional_and_carries_the_collectors_public_key(tmp_path, config):
    """Absent, console connect is not configured; present, the gateway holds the collector's
    public key and its id, and nothing that opens a sealed key."""
    _, human = load(tmp_path, config)
    assert human.scout is None
    _, human = load(tmp_path, config | {"scout": {}})
    assert human.scout is None
    public, private = collector_block(tmp_path)
    _, human = load(tmp_path, config | {"scout": {"collector": public}})
    assert human.scout is not None and human.scout.collector is not None
    assert human.scout.collector.key_id == public["key_id"]
    assert private not in repr(human)


@pytest.mark.parametrize(
    "change,field",
    [
        ({"public_key": "AAAA"}, "public_key"),
        ({"public_key": "not base64 at all"}, "public_key"),
        ({"key_id": "ck1-0000000000000000"}, "key_id"),
        ({"note": "VALUE-a91f2e"}, "note"),
    ],
    ids=["short", "not-base64", "wrong-id", "extra"],
)
def test_mc2_a_scout_block_that_is_not_a_collector_key_is_refused_naming_the_field(
    tmp_path, config, change, field
):
    public, _ = collector_block(tmp_path)
    block = {"collector": public | change}
    path = tmp_path / "private.json"
    path.write_text(json.dumps(config | {"scout": block}), encoding="utf-8")
    with pytest.raises(ValueError) as refused:
        read_configuration(path)
    message = str(refused.value)
    assert "scout" in message and field in message
    for value in change.values():
        assert value not in message.replace(field, "")
    assert public["public_key"] not in message
    with pytest.raises(ValueError, match="^Invalid runtime configuration$"):
        load(tmp_path, config | {"scout": block})


def test_mc2_a_changed_collector_key_is_a_restart_not_a_reload(tmp_path, config):
    public, _ = collector_block(tmp_path)
    config["scout"] = {"collector": public}
    path = tmp_path / "private.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    db = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    try:
        runtime, human = load_runtime(path, db)
        baseline = read_configuration(path)
        replacement, _ = collector_block(tmp_path / "next")
        config["scout"] = {"collector": replacement}
        path.write_text(json.dumps(config), encoding="utf-8")
        reload = reload_keys(path, runtime, human, baseline)
        assert (reload.state, reload.code) == ("refused", "CONFIGURATION_CHANGED")
        assert human.scout is not None and human.scout.collector is not None
        assert human.scout.collector.key_id == public["key_id"]
    finally:
        for connector in runtime.connectors.values():
            connector.close()
        db.close()


ENTRA_CLIENT = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"


def entra_block(**changes):
    return {
        "client_id": ENTRA_CLIENT,
        "authority": "organizations",
        "display_name": "Synthetic Scout",
        **changes,
    }


def test_mc3_the_scout_entra_block_names_the_platform_app_beside_the_collector(tmp_path, config):
    """With `entra` beside `collector`, an administrator may connect Microsoft Entra from the
    console: the platform app's client id, the authority its sign-in uses, and the name a
    directory administrator sees for it. Every value is public."""
    public, _ = collector_block(tmp_path)
    _, human = load(tmp_path, config | {"scout": {"collector": public}})
    assert human.scout is not None and human.scout.entra is None
    for authority in ("organizations", "11111111-2222-3333-4444-555555555555"):
        _, human = load(
            tmp_path,
            config | {"scout": {"collector": public, "entra": entra_block(authority=authority)}},
        )
        assert human.scout is not None and human.scout.entra is not None
        assert (
            human.scout.entra.client_id,
            human.scout.entra.authority,
            human.scout.entra.display_name,
        ) == (ENTRA_CLIENT, authority, "Synthetic Scout")


@pytest.mark.parametrize(
    "change,field",
    [
        ({"client_id": "VALUE-not-a-guid"}, "client_id"),
        ({"authority": "common"}, "authority"),
        ({"authority": "consumers"}, "authority"),
        ({"authority": "VALUE-https://example.test/tenant"}, "authority"),
        ({"display_name": "<b>VALUE-Scout</b>"}, "display_name"),
        ({"display_name": "VALUE-Scout & Co"}, "display_name"),
        ({"display_name": ""}, "display_name"),
        ({"display_name": "VALUE-" + "x" * 91}, "display_name"),
        ({"display_name": "VALUE-line\nbreak"}, "display_name"),
        ({"note": "VALUE-a91f2e"}, "note"),
    ],
    ids=[
        "client",
        "common",
        "consumers",
        "url",
        "markup",
        "ampersand",
        "empty",
        "long",
        "control",
        "extra",
    ],
)
def test_mc3_a_scout_entra_block_it_cannot_use_is_refused_naming_the_field(
    tmp_path, config, change, field
):
    public, _ = collector_block(tmp_path)
    path = tmp_path / "private.json"
    path.write_text(
        json.dumps(config | {"scout": {"collector": public, "entra": entra_block(**change)}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError) as refused:
        read_configuration(path)
    message = str(refused.value)
    assert "scout" in message and "entra" in message and field in message
    for value in change.values():
        if value:
            assert value not in message
            assert "VALUE" not in message
    with pytest.raises(ValueError, match="^Invalid runtime configuration$"):
        load(tmp_path, config | {"scout": {"collector": public, "entra": entra_block(**change)}})


def test_mc3_the_platform_app_is_accepted_only_beside_the_collector(tmp_path, config):
    """Connecting Entra creates a connection only the collector can read, so a deployment that
    names the platform app and no collector is refused, naming the blocks and no value."""
    path = tmp_path / "private.json"
    path.write_text(json.dumps(config | {"scout": {"entra": entra_block()}}), encoding="utf-8")
    with pytest.raises(ValueError) as refused:
        read_configuration(path)
    message = str(refused.value)
    assert "scout" in message and "entra" in message and "collector" in message
    assert ENTRA_CLIENT not in message


def test_mc3_a_changed_platform_app_is_a_restart_not_a_reload(tmp_path, config):
    public, _ = collector_block(tmp_path)
    config["scout"] = {"collector": public, "entra": entra_block()}
    path = tmp_path / "private.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    db = Database("postgresql+psycopg://invalid:invalid@127.0.0.1:1/execbound")
    try:
        runtime, human = load_runtime(path, db)
        baseline = read_configuration(path)
        config["scout"] = {"collector": public, "entra": entra_block(display_name="Renamed")}
        path.write_text(json.dumps(config), encoding="utf-8")
        reload = reload_keys(path, runtime, human, baseline)
        assert (reload.state, reload.code) == ("refused", "CONFIGURATION_CHANGED")
        assert human.scout is not None and human.scout.entra is not None
        assert human.scout.entra.display_name == "Synthetic Scout"
    finally:
        for connector in runtime.connectors.values():
            connector.close()
        db.close()
