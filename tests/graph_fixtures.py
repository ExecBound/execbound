# SPDX-License-Identifier: AGPL-3.0-only
"""A tenant whose identity account is served by Graph rather than by a mock.

The mock world in ``identity_fixtures`` reaches a provider ExecBound configured and
verifies a signature that provider co-signed. This one reaches a synthetic Graph, compares
the composite itself and settles on ExecBound's own signed account of the exchange, which
is a different settlement path and needs a world of its own to exercise it.
"""

from uuid import uuid4

import httpx
import pytest
from sqlalchemy import text
from test_execution import registry as registry
from test_execution import world as world

from execbound.policy.store import activate_bundle, create_bundle, validate_bundle
from execbound.provider.composite import graph_user_composite
from execbound.provider.graph import GraphCredential, GraphUserWriter
from execbound.provider.graph_connector import GraphConnectionConfig, GraphConnector
from execbound_harness.fake_graph import CLIENT, DIRECTORY, SECRET, Scenario, serving
from execbound_harness.fake_graph import transport as fake_transport
from execbound_harness.identity_demo import identity_bundle

USER_ID = "6f1b0c2e-6f40-4a2c-9a3f-2f6c0b1d7e55"
USER = {
    "id": USER_ID,
    "accountEnabled": True,
    "userPrincipalName": "agent@contoso.onmicrosoft.com",
    "onPremisesSyncEnabled": None,
}
SIGNING_KEY_ID = "connector-v1"
SIGNING_KEY = b"fixture-only-connector-signing-key-32"
ROTATED_KEY_ID = "connector-v2"
ROTATED_KEY = b"fixture-only-connector-rotated-key-32"
ACTION = "identity.disable"


def graph_scenario(**changes):
    return Scenario(users={USER_ID: {**USER, **changes}})


@pytest.fixture
def graph_world(world, db, admin_engine):
    """One tenant, one Graph account, one identity whose frozen version is its composite.

    The resource's version is the composite the connector will compute from its own read,
    because that comparison is the whole precondition here: a fixture that froze an
    arbitrary string would exercise only the mismatch path.
    """
    result = {**world, **{key: uuid4() for key in ("account", "inventory", "incident_source")}}
    result.update({key: uuid4() for key in ("target", "canonical", "incident")})
    tenant = world["identity"].tenant_id
    p = {
        **result,
        "t": tenant,
        "p": world["human"].principal_id,
        "n": world["clock"].now(),
        "provider_id": USER_ID,
        "version": graph_user_composite(USER),
    }
    with admin_engine.begin() as conn:
        conn.execute(
            text("""INSERT INTO execbound.connector_accounts
                (tenant_id,account_id,provider,space_id)
                VALUES (:t,:account,'graph', 
                    (SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"""),
            p,
        )
        conn.execute(
            text("""INSERT INTO execbound.context_sources
                (tenant_id,account_id,source_id,kind,allowed_writers) VALUES
                (:t,:account,:inventory,'inventory',ARRAY['inventory_sync']),
                (:t,:account,:incident_source,'incident',ARRAY['soc_analyst'])"""),
            p,
        )
        # The catalog binds exactly one Graph operation, `identity.disable` to `disable`,
        # and an account is bound to exactly one provider. So a Graph account maps that
        # action and no other: a mapping for `identity.enable` under this provider names a
        # binding the catalog does not hold, and bundle validation refuses it.
        conn.execute(
            text("""INSERT INTO execbound.operation_mappings
                (tenant_id,operation_ref,account_id,provider,resource_type,action,
                 provider_operation,mapping_version,schema_version,context_contract_version)
                VALUES (:t,:action,:account,'graph','identity',:action,'disable',
                        'map-v1','action.v1','identity-control.v1')"""),
            {**p, "action": ACTION},
        )
        conn.execute(text("INSERT INTO execbound.canonical_targets VALUES (:t,:canonical,:n)"), p)
        conn.execute(
            text("""INSERT INTO execbound.resources
                (tenant_id,account_id,provider,resource_type,resource_id,provider_id,
                 version,source_id,environment,criticality,privilege_class,observed_at)
                VALUES (:t,:account,'graph','identity',:target,:provider_id,
                        :version,:inventory,'development',1,'standard',:n)"""),
            p,
        )
        conn.execute(
            text("""INSERT INTO execbound.resource_identities
                VALUES (:t,:account,'graph','identity',:target,:canonical)"""),
            p,
        )
        conn.execute(
            text("""INSERT INTO execbound.incidents
                (tenant_id,account_id,provider,resource_type,incident_id,resource_id,
                 source_id,version,status,severity,observed_at)
                VALUES (:t,:account,'graph','identity',:incident,:target,
                        :incident_source,'incident-v1','OPEN','CRITICAL',:n)"""),
            p,
        )
        conn.execute(
            text("""INSERT INTO execbound.approval_scopes
                (tenant_id,approver_id,canonical_target_id,action, space_id)
                VALUES (:t,:p,:canonical,:action, 
                    (SELECT space_id FROM execbound.spaces WHERE tenant_id = :t))"""),
            {**p, "action": ACTION},
        )
    # The shared identity bundle names all three identity actions. This account binds one,
    # so the bundle is narrowed to it rather than the account widened to actions Graph has
    # no binding for.
    full = identity_bundle(tenant, result["account"], mapping_version="map-v1")
    bundle = full.model_copy(
        update={
            "mappings": tuple(m for m in full.mappings if m.operation_ref == ACTION),
            "limits": tuple(rule for rule in full.limits if rule.action == ACTION),
        }
    )
    create_bundle(db, world["admin"], bundle, world["clock"])
    validate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    activate_bundle(db, world["admin"], bundle.bundle_id, world["clock"])
    result["bundle"] = bundle
    return result


def graph_connection(world, *, keys=None, signing_key_id=SIGNING_KEY_ID, secret=SECRET):
    return GraphConnectionConfig(
        world["identity"].tenant_id,
        world["account"],
        GraphCredential(DIRECTORY, CLIENT, secret),
        keys or {SIGNING_KEY_ID: SIGNING_KEY},
        signing_key_id,
    )


def connector_for(server, world, **changes):
    client = httpx.Client(transport=fake_transport(server), follow_redirects=False)
    config = graph_connection(world, **changes)
    return GraphConnector(config, GraphUserWriter(config.credential, client))


@pytest.fixture
def graph_directory():
    with serving(graph_scenario()) as server:
        yield server


@pytest.fixture
def graph_connector(graph_directory, graph_world):
    connector = connector_for(graph_directory, graph_world)
    try:
        yield connector
    finally:
        connector.close()
