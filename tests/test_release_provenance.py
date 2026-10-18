# SPDX-License-Identifier: AGPL-3.0-only
"""The release provenance document and its licence disposition."""

import argparse
import importlib.metadata as metadata
import importlib.util
import json
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("release_provenance", "scripts/release_provenance.py")
assert spec is not None and spec.loader is not None
release_provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_provenance)

_notices_spec = importlib.util.spec_from_file_location(
    "third_party_notices", "scripts/third_party_notices.py"
)
assert _notices_spec is not None and _notices_spec.loader is not None
notices = importlib.util.module_from_spec(_notices_spec)
sys.modules.setdefault("third_party_notices", notices)
_notices_spec.loader.exec_module(notices)

DOCKERFILE = """
FROM python:3.13-slim-bookworm@sha256:{a} AS builder
COPY --from=ghcr.io/astral-sh/uv:0.12.13@sha256:{b} /uv /bin/uv
FROM python:3.13-slim-bookworm@sha256:{a}
""".format(a="a" * 64, b="b" * 64)


def sbom(tmp_path: Path, components: list[dict]) -> Path:
    path = tmp_path / "sbom.cdx.json"
    path.write_text(json.dumps({"components": components}), encoding="utf-8")
    return path


def component(name: str, version: str, licenses: list[dict] | None = None) -> dict:
    record = {"name": name, "version": version}
    if licenses is not None:
        record["licenses"] = licenses
    return record


def test_every_licence_form_cyclonedx_uses_is_read(tmp_path):
    path = sbom(
        tmp_path,
        [
            component("by-id", "1", [{"license": {"id": "MIT"}}]),
            component("by-name", "1", [{"license": {"name": "BSD-3-Clause"}}]),
            component("by-expression", "1", [{"expression": "Apache-2.0 OR MIT"}]),
        ],
    )
    counts = release_provenance.disposition(path)["counts"]
    assert counts == {"Apache-2.0 OR MIT": 1, "BSD-3-Clause": 1, "MIT": 1}


def test_copyleft_and_undeclared_components_need_a_decision(tmp_path):
    path = sbom(
        tmp_path,
        [
            component("permissive", "1", [{"license": {"id": "MIT"}}]),
            component("weak-copyleft", "2", [{"license": {"id": "MPL-2.0"}}]),
            component("strong-copyleft", "3", [{"license": {"id": "LGPL-3.0-only"}}]),
            component("silent", "4"),
        ],
    )
    summary = release_provenance.disposition(path)
    flagged = {item["component"]: item["reasons"] for item in summary["needs_decision"]}
    assert flagged == {
        "silent": ["undeclared"],
        "strong-copyleft": ["copyleft"],
        "weak-copyleft": ["copyleft"],
    }
    # A permissive component is counted but never demands a decision.
    assert "permissive" not in flagged and summary["components"] == 4


def test_an_unreadable_sbom_reports_itself_rather_than_an_empty_disposition(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    for path in (broken, tmp_path / "absent.json"):
        summary = release_provenance.disposition(path)
        # Silence would read as "no components and nothing to decide", which is the lie.
        assert summary["readable"] is False and summary["components"] is None
        assert summary["needs_decision"] == []


def test_an_expressions_spacing_does_not_split_its_count(tmp_path):
    # cedarpy's crate SBOM writes one crate's expression with doubled spaces.
    path = sbom(
        tmp_path,
        [
            component("spaced", "1", [{"expression": "Apache-2.0  OR  MIT"}]),
            component("plain", "1", [{"expression": "Apache-2.0 OR MIT"}]),
        ],
    )
    assert release_provenance.disposition(path)["counts"] == {"Apache-2.0 OR MIT": 2}


CEDARPY = "4.12.1"
INDEX = "registry+https://github.com/rust-lang/crates.io-index"


def crate(name: str, version: str, licenses: list[dict] | None = None) -> dict:
    """A crate as cargo-cyclonedx records it in the SBOM cedarpy's wheel bundles."""
    record = {
        "bom-ref": f"{INDEX}#{name}@{version}",
        "hashes": [{"alg": "SHA-256", "content": "f" * 64}],
        "name": name,
        "purl": f"pkg:cargo/{name}@{version}",
        "type": "library",
        "version": version,
    }
    if licenses is not None:
        record["licenses"] = licenses
    return record


def crate_sbom(*crates: dict, version: str = CEDARPY) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {
                "bom-ref": f"path+file:///build/cedar-py#cedarpy@{version}",
                "name": "cedarpy",
                "version": version,
            }
        },
        "components": list(crates),
    }


def release_sbom(*extra: dict, version: str = CEDARPY) -> dict:
    """What `cyclonedx-py environment` writes for the image's environment, cut down."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "bom-ref": f"cedarpy=={version}",
                "name": "cedarpy",
                "purl": f"pkg:pypi/cedarpy@{version}",
                "type": "library",
                "version": version,
            },
            {
                "bom-ref": "anyio==4.11.0",
                "licenses": [{"license": {"id": "MIT"}}],
                "name": "anyio",
                "type": "library",
                "version": "4.11.0",
            },
            *extra,
        ],
        "dependencies": [{"ref": f"cedarpy=={version}"}, {"ref": "anyio==4.11.0"}],
    }


def refs(components: list[dict]) -> list[str]:
    """Every bom-ref in a component list, nested ones included."""
    found = []
    for item in components:
        if "bom-ref" in item:
            found.append(item["bom-ref"])
        found += refs(item.get("components", []))
    return found


def test_the_crates_compiled_into_cedarpy_are_listed_inside_its_component(tmp_path):
    crates = crate_sbom(
        crate("anyhow", "1.0.104", [{"expression": "MIT OR Apache-2.0"}]),
        crate("unicode-ident", "1.0.18", [{"expression": "(MIT OR Apache-2.0) AND Unicode-3.0"}]),
    )
    release = release_sbom()
    nested = release_provenance.nest(release, crates, parent="cedarpy", version=CEDARPY)

    # The top level is still the Python environment, in the same order: only the cedarpy
    # component gains the crates inside it.
    assert [c["name"] for c in nested["components"]] == ["cedarpy", "anyio"]
    assert nested["dependencies"] == release["dependencies"]
    inside = nested["components"][0]["components"]
    assert [(c["name"], c["version"]) for c in inside] == [
        ("anyhow", "1.0.104"),
        ("unicode-ident", "1.0.18"),
    ]
    # Each crate keeps what the wheel's SBOM says of it: its licence, package URL and hash.
    for listed, original in zip(inside, crates["components"], strict=True):
        assert {k: v for k, v in listed.items() if k != "bom-ref"} == {
            k: v for k, v in original.items() if k != "bom-ref"
        }
    # Every reference in the document is unique, and a crate's is its own reference inside
    # cedarpy's, so a second wheel bundling the same crate could never collide with it.
    every = refs(nested["components"])
    assert len(every) == len(set(every)) == 4
    assert inside[0]["bom-ref"] == f"cedarpy=={CEDARPY}|{INDEX}#anyhow@1.0.104"
    # Neither input is changed.
    assert "components" not in release["components"][0]
    assert crates["components"][0]["bom-ref"] == f"{INDEX}#anyhow@1.0.104"


@pytest.mark.parametrize(
    ("release", "crates", "reason"),
    [
        # Another version's crates would describe a wheel the image does not carry.
        (release_sbom(version="4.11.0"), crate_sbom(crate("a", "1")), "not the 4.12.1"),
        (release_sbom(), crate_sbom(crate("a", "1"), version="4.11.0"), "built from cedarpy"),
        ({"components": []}, crate_sbom(crate("a", "1")), "0 times"),
        (
            release_sbom({"name": "CedarPy", "version": CEDARPY}),
            crate_sbom(crate("a", "1")),
            "2 times",
        ),
        ({"components": "none"}, crate_sbom(crate("a", "1")), "lists no components"),
        (release_sbom(), {"components": "none"}, "lists no crates"),
        (release_sbom(), [], "not a JSON object"),
        (
            release_sbom({"bom-ref": f"cedarpy=={CEDARPY}|{INDEX}#a@1", "name": "x"}),
            crate_sbom(crate("a", "1")),
            "more than once",
        ),
    ],
)
def test_crates_that_cannot_be_cedarpys_are_refused(release, crates, reason):
    with pytest.raises(release_provenance.NestRefused, match=reason):
        release_provenance.nest(release, crates, parent="cedarpy", version=CEDARPY)


def test_crates_are_never_listed_twice(tmp_path):
    crates = crate_sbom(crate("a", "1", [{"expression": "MIT"}]))
    once = release_provenance.nest(release_sbom(), crates, parent="cedarpy", version=CEDARPY)
    with pytest.raises(release_provenance.NestRefused, match="already lists"):
        release_provenance.nest(once, crates, parent="cedarpy", version=CEDARPY)


def nested_sbom(tmp_path: Path, *crates: dict, extra: tuple[dict, ...] = ()) -> Path:
    document = release_provenance.nest(
        release_sbom(*extra), crate_sbom(*crates), parent="cedarpy", version=CEDARPY
    )
    path = tmp_path / "sbom.cdx.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_a_copyleft_or_undeclared_crate_inside_cedarpy_needs_a_decision(tmp_path):
    path = nested_sbom(
        tmp_path,
        crate("permissive", "1", [{"expression": "MIT OR Apache-2.0"}]),
        crate("gpl-crate", "2", [{"expression": "GPL-3.0-only"}]),
        crate("silent-crate", "3"),
    )
    summary = release_provenance.disposition(path)
    flagged = {item["component"]: item for item in summary["needs_decision"]}
    # cedarpy itself declares nothing cyclonedx-py reads; that was already the case.
    assert set(flagged) == {"cedarpy", "gpl-crate", "silent-crate"}
    assert flagged["gpl-crate"] == {
        "component": "gpl-crate",
        "version": "2",
        "licenses": ["GPL-3.0-only"],
        "reasons": ["copyleft"],
        "within": ["cedarpy"],
    }
    assert flagged["silent-crate"]["reasons"] == ["undeclared"]
    assert flagged["silent-crate"]["within"] == ["cedarpy"]
    # A top-level component is not said to be inside anything.
    assert "within" not in flagged["cedarpy"]
    # Every component is counted, the crates inside cedarpy included.
    assert summary["components"] == 5
    assert summary["counts"]["MIT OR Apache-2.0"] == 1


def test_a_component_list_that_is_not_a_list_makes_the_sbom_unreadable(tmp_path):
    path = sbom(tmp_path, [{"name": "cedarpy", "version": "1", "components": "crates"}])
    summary = release_provenance.disposition(path)
    assert summary["readable"] is False and summary["components"] is None


def build(tmp_path: Path, **changes) -> dict:
    (tmp_path / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
    (tmp_path / "uv.lock").write_text("lock", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("project", encoding="utf-8")
    if not (tmp_path / "sbom.cdx.json").exists():
        sbom(tmp_path, [component("only", "1", [{"license": {"id": "MIT"}}])])
    values = {
        "output": tmp_path / "provenance.json",
        "sbom": "sbom.cdx.json",
        "dockerfile": "Dockerfile",
        "image_tag": "execbound:ci",
        "image_id": "sha256:" + "c" * 64,
        "image_distributions": "",
        "repository": "ExecBound/execbound",
        "revision": "abc123",
        "ref": "refs/pull/1/merge",
        "workflow": "Foundation checks",
        "run": "42",
        "runner": "github-hosted",
    }
    values.update(changes)
    return release_provenance.provenance(argparse.Namespace(**values), tmp_path)


def test_the_document_binds_the_artifact_to_its_source_and_pinned_inputs(tmp_path):
    document = build(tmp_path)
    assert document["source"] == {
        "repository": "ExecBound/execbound",
        "revision": "abc123",
        "ref": "refs/pull/1/merge",
    }
    # Both digest-pinned images the Dockerfile names, deduplicated across its two stages.
    assert document["inputs"]["base_images"] == [
        "ghcr.io/astral-sh/uv:0.12.13@sha256:" + "b" * 64,
        "python:3.13-slim-bookworm@sha256:" + "a" * 64,
    ]
    for key in ("uv_lock_sha256", "pyproject_sha256", "dockerfile_sha256"):
        assert len(document["inputs"][key]) == 64
    assert document["artifact"]["image_id"] == "sha256:" + "c" * 64
    assert len(document["artifact"]["sbom_sha256"]) == 64


def test_signing_and_deployment_are_recorded_as_gaps_never_as_capabilities(tmp_path):
    document = build(tmp_path)
    assert document["signing"]["signed"] is False and document["signing"]["gap"]
    assert document["deployment"]["deployed"] is False and document["deployment"]["gap"]
    # Nothing is pushed, so claiming a registry digest would be inventing one.
    assert document["artifact"]["registry_digest"] is None


def test_a_missing_image_id_is_null_rather_than_an_empty_string(tmp_path):
    assert build(tmp_path, image_id="")["artifact"]["image_id"] is None


def image_distributions(tmp_path: Path, rows: list[list[str]]) -> Path:
    path = tmp_path / "image-distributions.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    return path


def test_a_matching_sbom_and_image_report_no_drift(tmp_path):
    sbom(tmp_path, [component("Alpha", "1.0"), component("beta", "2.0")])
    # The image reports its own casing; the comparison is case-insensitive on the name.
    installed = image_distributions(tmp_path, [["alpha", "1.0"], ["Beta", "2.0"]])
    assert release_provenance.drift(tmp_path / "sbom.cdx.json", installed) == ([], [])
    document = build(tmp_path, image_distributions=str(installed.name))
    assert document["artifact"]["sbom_matches_image"] is True
    assert document["artifact"]["sbom_drift"] == {
        "listed_but_absent": [],
        "present_but_unlisted": [],
    }


def test_drift_in_either_direction_is_reported_and_fails_the_match(tmp_path):
    sbom(tmp_path, [component("kept", "1.0"), component("listed-only", "9.9")])
    installed = image_distributions(tmp_path, [["kept", "1.0"], ["shipped-only", "3.1"]])
    listed_but_absent, present_but_unlisted = release_provenance.drift(
        tmp_path / "sbom.cdx.json", installed
    )
    assert listed_but_absent == ["listed-only==9.9"]
    assert present_but_unlisted == ["shipped-only==3.1"]
    document = build(tmp_path, image_distributions=str(installed.name))
    assert document["artifact"]["sbom_matches_image"] is False


def test_the_crates_inside_cedarpy_are_not_compared_with_the_images_distributions(tmp_path):
    """The image carries Python distributions, and the crates are compiled into one of them,
    so a crate is neither listed-but-absent nor a reason a real Python drift goes unseen."""
    nested_sbom(tmp_path, crate("anyhow", "1.0.104", [{"expression": "MIT"}]))
    matching = image_distributions(tmp_path, [["cedarpy", CEDARPY], ["anyio", "4.11.0"]])
    assert release_provenance.drift(tmp_path / "sbom.cdx.json", matching) == ([], [])
    document = build(tmp_path, image_distributions=matching.name)
    assert document["artifact"]["sbom_matches_image"] is True

    drifted = image_distributions(tmp_path, [["cedarpy", CEDARPY], ["anyio", "4.12.0"]])
    assert release_provenance.drift(tmp_path / "sbom.cdx.json", drifted) == (
        ["anyio==4.11.0"],
        ["anyio==4.12.0"],
    )
    document = build(tmp_path, image_distributions=drifted.name)
    assert document["artifact"]["sbom_matches_image"] is False


def test_a_version_change_alone_is_drift(tmp_path):
    sbom(tmp_path, [component("same", "1.0")])
    installed = image_distributions(tmp_path, [["same", "1.1"]])
    assert release_provenance.drift(tmp_path / "sbom.cdx.json", installed) == (
        ["same==1.0"],
        ["same==1.1"],
    )


def test_an_unreadable_image_listing_is_unknown_rather_than_a_match(tmp_path):
    sbom(tmp_path, [component("only", "1")])
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert release_provenance.drift(tmp_path / "sbom.cdx.json", broken) is None
    document = build(tmp_path, image_distributions="broken.json")
    # Unknown is never recorded as verified.
    assert document["artifact"]["sbom_matches_image"] is None


def test_without_an_image_listing_the_comparison_is_simply_not_made(tmp_path):
    document = build(tmp_path, image_distributions="")
    assert document["artifact"]["sbom_matches_image"] is None
    assert document["artifact"]["sbom_drift"] is None


DIGEST = "sha256:" + "d" * 64
IDENTITY = "https://github.com/ExecBound/execbound/.github/workflows/release.yml@refs/tags/v0.1.0"
ISSUER = "https://token.actions.githubusercontent.com"
RELEASE = {
    "reference": "ghcr.io/execbound/execbound",
    "digest": DIGEST,
    "identity": IDENTITY,
    "issuer": ISSUER,
}


def matched(tmp_path: Path) -> dict:
    sbom(tmp_path, [component("only", "1")])
    installed = image_distributions(tmp_path, [["only", "1"]])
    return build(tmp_path, image_distributions=str(installed.name))


def test_a_release_records_the_digest_and_the_signature_and_nothing_else_changes(tmp_path):
    document = matched(tmp_path)
    amended = release_provenance.amend(document, **RELEASE)
    assert amended["artifact"]["registry_reference"] == "ghcr.io/execbound/execbound"
    assert amended["artifact"]["registry_digest"] == DIGEST
    assert amended["signing"] == {
        "signed": True,
        "method": release_provenance.SIGNING_METHOD,
        "certificate_identity": IDENTITY,
        "certificate_oidc_issuer": ISSUER,
        "verify": (
            f"cosign verify ghcr.io/execbound/execbound@{DIGEST}"
            f" --certificate-identity {IDENTITY} --certificate-oidc-issuer {ISSUER}"
        ),
    }
    # Everything the build recorded is exactly what it was, and the build's own copy is
    # untouched.
    for key in set(document) - {"artifact", "signing"}:
        assert amended[key] == document[key], key
    unchanged = {k: v for k, v in amended["artifact"].items() if not k.startswith("registry_")}
    assert unchanged == {k: v for k, v in document["artifact"].items() if k != "registry_digest"}
    assert document["signing"]["signed"] is False
    assert document["artifact"]["registry_digest"] is None


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"reference": "ghcr.io/execbound/execbound:0.1.0"}, "without a tag"),
        ({"reference": f"ghcr.io/execbound/execbound@{DIGEST}"}, "without a tag"),
        ({"reference": "execbound"}, "without a tag"),
        ({"reference": "GHCR.io/ExecBound/execbound"}, "without a tag"),
        ({"digest": "sha256:" + "d" * 63}, "not a sha256 digest"),
        ({"digest": "d" * 64}, "not a sha256 digest"),
        ({"identity": "http://github.com/x"}, "identity"),
        ({"identity": "https://github.com/a b"}, "identity"),
        ({"issuer": ""}, "issuer"),
    ],
)
def test_a_value_that_cannot_be_a_release_is_refused(tmp_path, change, reason):
    with pytest.raises(release_provenance.AmendRefused, match=reason):
        release_provenance.amend(matched(tmp_path), **{**RELEASE, **change})


def test_only_a_build_whose_sbom_matched_its_image_can_become_a_release(tmp_path):
    sbom(tmp_path, [component("only", "1")])
    for listing in ("", str(image_distributions(tmp_path, [["other", "1"]]).name)):
        document = build(tmp_path, image_distributions=listing)
        with pytest.raises(release_provenance.AmendRefused, match="SBOM"):
            release_provenance.amend(document, **RELEASE)


def test_a_document_that_is_signed_already_or_of_another_format_is_refused(tmp_path):
    signed = release_provenance.amend(matched(tmp_path), **RELEASE)
    with pytest.raises(release_provenance.AmendRefused, match="already records a signature"):
        release_provenance.amend(signed, **RELEASE)
    with pytest.raises(release_provenance.AmendRefused, match="not a execbound"):
        release_provenance.amend({**matched(tmp_path), "format": "other"}, **RELEASE)
    with pytest.raises(release_provenance.AmendRefused, match="no artifact"):
        release_provenance.amend({"format": release_provenance.FORMAT}, **RELEASE)


def project(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
    (tmp_path / "uv.lock").write_text("lock", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("project", encoding="utf-8")
    sbom(tmp_path, [component("only", "1", [{"license": {"id": "MIT"}}])])
    image_distributions(tmp_path, [["only", "1"]])


def written(tmp_path: Path, *arguments: str) -> dict:
    release_provenance.main(
        [
            "--output",
            str(tmp_path / "provenance.json"),
            "--sbom",
            "sbom.cdx.json",
            "--image-distributions",
            "image-distributions.json",
            *arguments,
        ]
    )
    return json.loads((tmp_path / "provenance.json").read_text(encoding="utf-8"))


def test_the_runner_is_the_one_github_names_or_local(tmp_path, monkeypatch, capsys):
    project(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    assert written(tmp_path)["build"]["runner"] == "github-hosted"
    assert written(tmp_path, "--runner", "self-hosted")["build"]["runner"] == "self-hosted"
    monkeypatch.delenv("RUNNER_ENVIRONMENT")
    assert written(tmp_path)["build"]["runner"] == "local"


def test_the_command_line_says_which_component_a_named_crate_is_inside(
    tmp_path, monkeypatch, capsys
):
    project(tmp_path)
    nested_sbom(tmp_path, crate("gpl-crate", "2", [{"expression": "GPL-3.0-only"}]))
    image_distributions(tmp_path, [["cedarpy", CEDARPY], ["anyio", "4.11.0"]])
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        written(tmp_path)
    lines = capsys.readouterr().out.splitlines()
    assert "  gpl-crate 2 inside cedarpy: ['GPL-3.0-only'] (['copyleft'])" in lines
    assert "  cedarpy 4.12.1: ['(none declared)'] (['undeclared'])" in lines


def release_arguments() -> list[str]:
    return [
        "--image-reference",
        RELEASE["reference"],
        "--registry-digest",
        DIGEST,
        "--signature-identity",
        IDENTITY,
        "--signature-issuer",
        ISSUER,
    ]


def test_the_command_line_amends_the_document_in_place(tmp_path, monkeypatch, capsys):
    project(tmp_path)
    monkeypatch.chdir(tmp_path)
    built = written(tmp_path)
    release_provenance.main(["--amend", str(tmp_path / "provenance.json"), *release_arguments()])
    amended = json.loads((tmp_path / "provenance.json").read_text(encoding="utf-8"))
    assert amended == release_provenance.amend(built, **RELEASE)


def test_the_command_line_refuses_a_document_it_cannot_amend(tmp_path, monkeypatch, capsys):
    project(tmp_path)
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "provenance.json"
    for content in ("{not json", "[]", json.dumps({"format": "other"})):
        target.write_text(content, encoding="utf-8")
        with pytest.raises(SystemExit) as stopped:
            release_provenance.main(["--amend", str(target), *release_arguments()])
        assert stopped.value.code == 1
        assert target.read_text(encoding="utf-8") == content
        assert capsys.readouterr().err.startswith("release_provenance: ")


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["--output", "a.json", "--amend", "b.json"],
        ["--output", "a.json", "--registry-digest", DIGEST],
        ["--amend", "b.json", "--registry-digest", DIGEST],
        ["--nest-crates", "a.json", "--output", "b.json"],
        ["--nest-crates", "a.json", "--registry-digest", DIGEST],
    ],
)
def test_the_command_line_takes_a_build_or_a_complete_release(arguments, capsys):
    with pytest.raises(SystemExit) as stopped:
        release_provenance.main(arguments)
    assert stopped.value.code == 2


def test_the_command_line_nests_the_crates_of_the_cedarpy_it_runs_beside(tmp_path, capsys):
    """Read from the wheel this interpreter has installed, as CI reads the image environment's
    own, by the same reader `THIRD_PARTY_NOTICES.md` is written with."""
    version = metadata.version("cedarpy")
    wheel_version, crates = notices.cedarpy_sbom()
    assert wheel_version == version
    path = tmp_path / "sbom.cdx.json"
    path.write_text(json.dumps(release_sbom(version=version)), encoding="utf-8")

    release_provenance.main(["--nest-crates", str(path)])

    document = json.loads(path.read_text(encoding="utf-8"))
    inside = document["components"][0]["components"]
    assert [(c["name"], c["version"]) for c in inside] == [
        (c["name"], c["version"]) for c in crates["components"]
    ]
    every = refs(document["components"])
    assert len(every) == len(set(every)) == len(crates["components"]) + 2
    assert json.loads(capsys.readouterr().out) == {
        "nested": len(crates["components"]),
        "within": f"cedarpy=={version}",
    }
    # DEPENDENCIES.md says every crate cedarpy bundles is permissive; the release's own
    # disposition holds it to that.
    summary = release_provenance.disposition(path)
    assert [item for item in summary["needs_decision"] if "within" in item] == []


def test_the_command_line_leaves_an_sbom_it_cannot_nest_into_as_it_was(tmp_path, capsys):
    path = tmp_path / "sbom.cdx.json"
    for content in ("{not json", "[]", json.dumps({"components": []})):
        path.write_text(content, encoding="utf-8")
        with pytest.raises(SystemExit) as stopped:
            release_provenance.main(["--nest-crates", str(path)])
        assert stopped.value.code == 1
        assert path.read_text(encoding="utf-8") == content
        assert capsys.readouterr().err.startswith("release_provenance: ")


def allowances(tmp_path: Path, entries: object) -> None:
    path = tmp_path / "releases" / "licence-allowances.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps({"allowances": entries}), encoding="utf-8")


def allowance(name: str, licenses: list[str], why: str = "its reason") -> dict:
    return {"component": name, "licenses": licenses, "why": why}


def flagged_project(tmp_path: Path) -> None:
    project(tmp_path)
    sbom(
        tmp_path,
        [
            component("only", "1", [{"license": {"id": "MIT"}}]),
            component("weak-copyleft", "2", [{"license": {"id": "MPL-2.0"}}]),
            component("silent", "3"),
        ],
    )
    image_distributions(tmp_path, [["only", "1"], ["weak-copyleft", "2"], ["silent", "3"]])


def test_a_licence_finding_with_no_allowance_fails_the_build(tmp_path, monkeypatch, capsys):
    flagged_project(tmp_path)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as stopped:
        written(tmp_path)
    assert stopped.value.code == 1
    out = capsys.readouterr().out
    assert "licence finding with no allowance: weak-copyleft 2: ['MPL-2.0']" in out
    assert "licence finding with no allowance: silent 3: ['(none declared)']" in out
    # The document is still written, so the reviewer reads exactly what failed.
    document = json.loads((tmp_path / "provenance.json").read_text(encoding="utf-8"))
    assert {item["component"] for item in document["licenses"]["unallowed"]} == {
        "weak-copyleft",
        "silent",
    }


def test_an_allowed_finding_passes_and_the_document_records_why(tmp_path, monkeypatch, capsys):
    flagged_project(tmp_path)
    allowances(
        tmp_path,
        [
            allowance("weak-copyleft", ["MPL-2.0"], "used unmodified, with its notice"),
            allowance("silent", ["(none declared)"], "ships Apache-2.0 text"),
        ],
    )
    monkeypatch.chdir(tmp_path)
    document = written(tmp_path)
    summary = document["licenses"]
    reasons = {item["component"]: item["allowed"] for item in summary["needs_decision"]}
    assert reasons == {
        "weak-copyleft": "used unmodified, with its notice",
        "silent": "ships Apache-2.0 text",
    }
    assert summary["unallowed"] == [] and summary["stale_allowances"] == []
    assert "allowed: used unmodified, with its notice" in capsys.readouterr().out


def test_an_allowance_does_not_cover_a_component_whose_licence_changed(tmp_path, monkeypatch):
    flagged_project(tmp_path)
    allowances(
        tmp_path,
        [allowance("weak-copyleft", ["MPL-1.1"]), allowance("silent", ["(none declared)"])],
    )
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        written(tmp_path)
    licences = json.loads((tmp_path / "provenance.json").read_text(encoding="utf-8"))["licenses"]
    assert [item["component"] for item in licences["unallowed"]] == ["weak-copyleft"]
    # The allowance written for the old licence now matches nothing, and says so.
    assert licences["stale_allowances"] == [{"component": "weak-copyleft", "licenses": ["MPL-1.1"]}]


def test_an_allowance_that_matches_nothing_fails_the_build(tmp_path, monkeypatch, capsys):
    project(tmp_path)
    allowances(tmp_path, [allowance("gone", ["GPL-3.0-only"])])
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as stopped:
        written(tmp_path)
    assert stopped.value.code == 1
    assert "allowance that matches nothing: gone ['GPL-3.0-only']" in capsys.readouterr().out


def test_a_component_name_matches_as_python_names_do(tmp_path, monkeypatch):
    flagged_project(tmp_path)
    allowances(
        tmp_path,
        [allowance("Weak_Copyleft", ["MPL-2.0"]), allowance("silent", ["(none declared)"])],
    )
    monkeypatch.chdir(tmp_path)
    assert written(tmp_path)["licenses"]["unallowed"] == []


@pytest.mark.parametrize(
    "entries",
    [
        [{"component": "silent", "licenses": ["(none declared)"]}],
        [{"component": "silent", "licenses": ["(none declared)"], "why": "  "}],
        [{"component": "silent", "licenses": [], "why": "a reason"}],
        [{"component": "", "licenses": ["(none declared)"], "why": "a reason"}],
        [allowance("silent", ["(none declared)"]), allowance("Silent", ["(none declared)"])],
        {"silent": "not a list"},
    ],
)
def test_an_allowance_with_no_reason_or_no_licence_is_refused(
    tmp_path, monkeypatch, capsys, entries
):
    flagged_project(tmp_path)
    allowances(tmp_path, entries)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as stopped:
        written(tmp_path)
    assert stopped.value.code == 1
    assert "releases/licence-allowances.json" in capsys.readouterr().err


def test_the_committed_allowances_each_give_their_reason():
    document = json.loads(Path("releases/licence-allowances.json").read_text(encoding="utf-8"))
    entries = release_provenance.read_allowances(Path("releases/licence-allowances.json"))
    assert entries == document["allowances"] and entries
    for entry in entries:
        assert len(entry["why"].split()) >= 8, entry["component"]
