# SPDX-License-Identifier: AGPL-3.0-only
"""Link a built image to the source, inputs, checks and licences that produced it.

The provenance document answers one question a reviewer or an auditor asks: which exact
revision, locked inputs and base images produced this artifact, and what was checked before
it existed. It also carries a licence disposition derived from the image's own SBOM, so an
undeclared or copyleft component cannot enter a release without appearing here.

A build's document records its signature and registry digest as absent, because a CI build
is never pushed or signed. `--amend` fills both in for a release, and only after the release
workflow has pushed the image and verified the signature over its digest (docs/RELEASE.md).
Nothing here claims a deployment: that is recorded as an explicit gap.

`--nest-crates` runs first, under the image environment's own interpreter. It lists the Rust
crates compiled into `cedarpy` inside cedarpy's component of the SBOM, from the CycloneDX SBOM
the installed wheel bundles (PEP 770), so the disposition reads their licences too.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import sys
from collections import Counter
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Licences that oblige a distributor to do something beyond attribution. Their presence is
# not a fault; letting one enter a release unnoticed is.
COPYLEFT = re.compile(r"\b(?:A?GPL|LGPL|MPL|EPL|CDDL|CPL|OSL|SSPL)\b", re.IGNORECASE)
BASE_IMAGE = re.compile(r"^FROM\s+(\S+@sha256:[0-9a-f]{64})", re.IGNORECASE | re.MULTILINE)
COPY_IMAGE = re.compile(r"^COPY\s+--from=(\S+@sha256:[0-9a-f]{64})", re.IGNORECASE | re.MULTILINE)
UNDECLARED = "(none declared)"
FORMAT = "execbound.release-provenance.v1"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# A registry path with no tag and no digest, which is what `cosign verify` takes before `@`.
REFERENCE = re.compile(r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?(?:/[a-z0-9][a-z0-9._-]*)+")
SIGNING_METHOD = "cosign keyless: a Sigstore certificate for the GitHub Actions OIDC identity"


class AmendRefused(ValueError):
    """A document or a value that cannot become a signed release's provenance."""


class NestRefused(ValueError):
    """Crates that cannot be listed as the ones compiled into a release SBOM's component."""


def digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def licences(component: dict[str, Any]) -> list[str]:
    """Every licence string a CycloneDX component declares, however it declares it."""
    found = []
    for entry in component.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("expression"), str):
            found.append(entry["expression"])
        licence = entry.get("license")
        if isinstance(licence, dict):
            value = licence.get("id") or licence.get("name")
            if isinstance(value, str):
                found.append(value)
    # Spacing is not meaning: one crate in cedarpy's SBOM writes `Apache-2.0  OR  MIT`.
    return [" ".join(value.split()) for value in found] or [UNDECLARED]


def walk(
    components: list[Any], within: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], dict[str, Any]]]:
    """Every component and the names of the ones it is listed inside, nested lists included.
    A nested list that is not a list is a ValueError: the SBOM cannot be read whole."""
    for component in components:
        if not isinstance(component, dict):
            continue
        yield within, component
        inside = component.get("components")
        if inside is None:
            continue
        if not isinstance(inside, list):
            raise ValueError(f"{component.get('name')}'s components are not a list")
        yield from walk(inside, (*within, str(component.get("name"))))


def disposition(sbom: Path) -> dict[str, Any]:
    """Summarize the SBOM's licences and name the components that need a decision.

    Every component is read, the ones listed inside another included: the crates compiled
    into cedarpy are listed inside its component, and one of them is named, with `within`,
    exactly as a Python distribution would be.
    """
    try:
        document = json.loads(sbom.read_text(encoding="utf-8"))
        components = document["components"]
        assert isinstance(components, list)
        walked = list(walk(components))
    except (OSError, ValueError, KeyError, TypeError, AssertionError):
        return {"readable": False, "components": None, "counts": {}, "needs_decision": []}
    counts: Counter[str] = Counter()
    needs_decision = []
    for within, component in walked:
        found = licences(component)
        counts.update(found)
        reasons = []
        if UNDECLARED in found:
            reasons.append("undeclared")
        if any(COPYLEFT.search(value) for value in found):
            reasons.append("copyleft")
        if reasons:
            item = {
                "component": component.get("name"),
                "version": component.get("version"),
                "licenses": found,
                "reasons": reasons,
            }
            if within:
                item["within"] = list(within)
            needs_decision.append(item)
    return {
        "readable": True,
        "components": len(walked),
        "counts": dict(sorted(counts.items())),
        "needs_decision": sorted(
            needs_decision,
            key=lambda item: (str(item["component"]).lower(), item.get("within", [])),
        ),
    }


def _canonical(name: object) -> str:
    """A distribution's name as packaging compares it (PEP 503)."""
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def nest(
    release: dict[str, Any], crates: dict[str, Any], *, parent: str, version: str
) -> dict[str, Any]:
    """The release SBOM with `crates`' components listed inside its `parent` component.

    `crates` is the CycloneDX SBOM a wheel bundles of what was compiled into it, and
    `version` is the version of the wheel it came from. Nested components are an assembly, not
    a dependency: the crates are part of the distribution, so the top level stays the Python
    environment the image's own distributions are compared with. Each crate keeps everything
    its SBOM says of it, and its reference becomes its own reference inside `parent`'s, so no
    two components in the document share one. Neither input is changed.
    """
    document = copy.deepcopy(release)
    components = document.get("components")
    if not isinstance(components, list):
        raise NestRefused("the release SBOM lists no components")
    matching = [
        c
        for c in components
        if isinstance(c, dict) and _canonical(c.get("name")) == _canonical(parent)
    ]
    if len(matching) != 1:
        raise NestRefused(f"the release SBOM lists {parent} {len(matching)} times, not once")
    (target,) = matching
    if str(target.get("version")) != version:
        raise NestRefused(
            f"the release SBOM lists {parent} {target.get('version')}, not the {version} whose"
            " crates these are"
        )
    if not isinstance(crates, dict):
        raise NestRefused(f"the SBOM {parent}'s wheel bundles is not a JSON object")
    metadata = crates.get("metadata")
    built = metadata.get("component") if isinstance(metadata, dict) else None
    if isinstance(built, dict) and "version" in built and str(built["version"]) != version:
        raise NestRefused(
            f"the crates were built from {parent} {built['version']}, not from {version}"
        )
    listed = crates.get("components")
    if not isinstance(listed, list) or not all(isinstance(c, dict) for c in listed):
        raise NestRefused(f"the SBOM {parent}'s wheel bundles lists no crates")
    if "components" in target:
        raise NestRefused(f"the release SBOM already lists components inside {parent}")
    prefix = str(target.get("bom-ref") or f"{target.get('name')}=={version}")
    inside = copy.deepcopy(listed)
    for _, crate in walk(inside):
        if "bom-ref" in crate:
            crate["bom-ref"] = f"{prefix}|{crate['bom-ref']}"
    target["components"] = inside
    seen: Counter[str] = Counter(str(c["bom-ref"]) for _, c in walk(components) if "bom-ref" in c)
    repeated = sorted(ref for ref, count in seen.items() if count > 1)
    if repeated:
        raise NestRefused(f"these references would be used more than once: {repeated}")
    return document


def installed_crates() -> tuple[str, dict[str, Any]]:
    """The installed cedarpy's version and the crate SBOM its wheel bundles, read by the same
    reader `THIRD_PARTY_NOTICES.md` is written with, so the two list the same crates."""
    module = sys.modules.get("third_party_notices")
    if module is None:
        path = Path(__file__).resolve().with_name("third_party_notices.py")
        spec = importlib.util.spec_from_file_location("third_party_notices", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["third_party_notices"] = module
        spec.loader.exec_module(module)
    version, document = module.cedarpy_sbom()
    return str(version), document


def installed_in_image(path: Path) -> set[tuple[str, str]] | None:
    """The distributions the built image actually carries, as (name, version) pairs."""
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
        return {(str(name).lower(), str(version)) for name, version in rows}
    except (OSError, ValueError, TypeError):
        return None


def drift(sbom: Path, image: Path) -> tuple[list[str], list[str]] | None:
    """What the SBOM claims but the image lacks, and what the image carries unlisted."""
    installed = installed_in_image(image)
    try:
        components = json.loads(sbom.read_text(encoding="utf-8"))["components"]
        listed = {(str(c["name"]).lower(), str(c["version"])) for c in components}
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if installed is None:
        return None
    return (
        sorted(f"{name}=={version}" for name, version in listed - installed),
        sorted(f"{name}=={version}" for name, version in installed - listed),
    )


def provenance(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    dockerfile = (root / args.dockerfile).read_text(encoding="utf-8")
    sbom = root / args.sbom
    licence_summary = disposition(sbom)
    # An SBOM that does not describe the artifact is worse than none: it is evidence for
    # something that did not ship. Record the comparison rather than assume it.
    difference = drift(sbom, root / args.image_distributions) if args.image_distributions else None
    matches = None if difference is None else not any(difference)
    return {
        "format": FORMAT,
        "generated_at": datetime.now(UTC).isoformat(),
        "source": {"repository": args.repository, "revision": args.revision, "ref": args.ref},
        "build": {
            "workflow": args.workflow,
            "run": args.run,
            "runner": args.runner,
            "builder": "docker build",
        },
        "inputs": {
            "uv_lock_sha256": digest(root / "uv.lock"),
            "pyproject_sha256": digest(root / "pyproject.toml"),
            "dockerfile_sha256": digest(root / args.dockerfile),
            # The console's lockfile and manifest are build inputs too: the Node stage installs
            # from the one and pins its package manager by the hash in the other.
            "pnpm_lock_sha256": digest(root / "console" / "pnpm-lock.yaml"),
            "console_package_sha256": digest(root / "console" / "package.json"),
            # Pinned by digest in the Dockerfile, so the build inputs are identifiable.
            "base_images": sorted(
                set(BASE_IMAGE.findall(dockerfile)) | set(COPY_IMAGE.findall(dockerfile))
            ),
        },
        "artifact": {
            "image_tag": args.image_tag,
            "image_id": args.image_id or None,
            # A build is not pushed anywhere, so no registry digest exists to record. A
            # release's is filled in by `--amend` once the image is pushed and signed.
            "registry_digest": None,
            "sbom": sbom.name,
            "sbom_sha256": digest(sbom),
            "sbom_matches_image": matches,
            "sbom_drift": (
                None
                if difference is None
                else {"listed_but_absent": difference[0], "present_but_unlisted": difference[1]}
            ),
        },
        "licenses": licence_summary,
        "checks": {
            "workflow": args.workflow,
            "note": (
                "The CI workflow's verify job on this revision is the check population: ruff, "
                "format, strict mypy, the full pytest suite on PostgreSQL, the validation and "
                "monitoring demonstrations, the backup round trip, the image smoke test and the "
                "installation from nothing. A release is built only from a revision on which "
                "that workflow passed on main (RELEASE.md)."
            ),
        },
        "signing": {
            "signed": False,
            "gap": (
                "This build is not signed. Only the release workflow signs, after it has pushed "
                "the image, and it records the signature here with --amend (RELEASE.md)."
            ),
        },
        "deployment": {
            "deployed": False,
            "gap": (
                "This document describes a build, not a deployment: no deploy approval, "
                "environment record or rollback reference is linked to it. The chain a "
                "deployment would have to record is documented in DEPLOYMENT.md."
            ),
        },
    }


def amend(
    document: dict[str, Any], *, reference: str, digest: str, identity: str, issuer: str
) -> dict[str, Any]:
    """The provenance of a release whose image was pushed and whose signature was verified: the
    registry digest the signature covers and the identity that made it. Every field the build
    recorded stays as it was. Only a build whose SBOM matched its image can become a release."""
    if document.get("format") != FORMAT:
        raise AmendRefused(f"not a {FORMAT} document")
    artifact, signing = document.get("artifact"), document.get("signing")
    if not isinstance(artifact, dict) or not isinstance(signing, dict):
        raise AmendRefused("the document has no artifact or signing block")
    if signing.get("signed") is not False:
        raise AmendRefused("the document already records a signature")
    if artifact.get("sbom_matches_image") is not True:
        raise AmendRefused("the SBOM was not shown to describe the image, so it cannot be released")
    if not REFERENCE.fullmatch(reference):
        raise AmendRefused(f"{reference!r} is not a registry path without a tag or a digest")
    if not DIGEST.fullmatch(digest):
        raise AmendRefused(f"{digest!r} is not a sha256 digest")
    for name, value in (("identity", identity), ("issuer", issuer)):
        if not re.fullmatch(r"https://[^\s]+", value):
            raise AmendRefused(f"the signature's {name} {value!r} is not an https address")
    amended = copy.deepcopy(document)
    amended["artifact"]["registry_reference"] = reference
    amended["artifact"]["registry_digest"] = digest
    amended["signing"] = {
        "signed": True,
        "method": SIGNING_METHOD,
        "certificate_identity": identity,
        "certificate_oidc_issuer": issuer,
        "verify": (
            f"cosign verify {reference}@{digest} --certificate-identity {identity}"
            f" --certificate-oidc-issuer {issuer}"
        ),
    }
    return amended


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--output", type=Path, help="write a build's document here")
    target.add_argument(
        "--amend",
        type=Path,
        help="record a pushed and verified release in this document, in place",
    )
    target.add_argument(
        "--nest-crates",
        type=Path,
        help=(
            "list the Rust crates compiled into cedarpy inside its component of this SBOM, in"
            " place, from the SBOM the wheel installed beside this interpreter bundles"
        ),
    )
    parser.add_argument("--image-reference", default="", help="with --amend: the registry path")
    parser.add_argument("--registry-digest", default="", help="with --amend: the pushed digest")
    parser.add_argument("--signature-identity", default="", help="with --amend")
    parser.add_argument("--signature-issuer", default="", help="with --amend")
    parser.add_argument(
        "--runner",
        # GitHub sets `github-hosted` or `self-hosted`; anywhere else the build ran locally.
        default=os.environ.get("RUNNER_ENVIRONMENT") or "local",
    )
    parser.add_argument("--sbom", default="local-data/release/sbom.cdx.json")
    parser.add_argument("--dockerfile", default="Dockerfile")
    parser.add_argument("--image-tag", default="")
    parser.add_argument("--image-id", default="")
    parser.add_argument(
        "--image-distributions",
        default="",
        help="JSON array of [name, version] pairs read out of the built image.",
    )
    parser.add_argument("--repository", default="")
    parser.add_argument("--revision", default="")
    parser.add_argument("--ref", default="")
    parser.add_argument("--workflow", default="")
    parser.add_argument("--run", default="")
    args = parser.parse_args(argv)
    release = (
        args.image_reference,
        args.registry_digest,
        args.signature_identity,
        args.signature_issuer,
    )
    if args.amend is None and any(release):
        parser.error("the registry and signature arguments go with --amend")
    if args.nest_crates is not None:
        try:
            document = json.loads(args.nest_crates.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise NestRefused(f"{args.nest_crates} does not hold a JSON object")
            version, crates = installed_crates()
            nested = nest(document, crates, parent="cedarpy", version=version)
        except (OSError, ValueError, ImportError) as error:
            # A missing wheel is an ImportError: importlib.metadata's PackageNotFoundError.
            print(f"release_provenance: {error}", file=sys.stderr)
            raise SystemExit(1) from None
        args.nest_crates.write_text(
            json.dumps(nested, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (target,) = [
            c
            for c in nested["components"]
            if isinstance(c, dict) and _canonical(c.get("name")) == "cedarpy"
        ]
        print(json.dumps({"nested": len(target["components"]), "within": target.get("bom-ref")}))
        return
    if args.amend is not None:
        if not all(release):
            parser.error("--amend needs all four registry and signature arguments")
        try:
            document = json.loads(args.amend.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise AmendRefused(f"{args.amend} does not hold a JSON object")
            amended = amend(
                document,
                reference=args.image_reference,
                digest=args.registry_digest,
                identity=args.signature_identity,
                issuer=args.signature_issuer,
            )
        except (OSError, ValueError) as error:
            print(f"release_provenance: {error}", file=sys.stderr)
            raise SystemExit(1) from None
        args.amend.write_text(json.dumps(amended, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps({"registry_digest": args.registry_digest, "signed": True}))
        return
    document = provenance(args, Path.cwd())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    summary = document["licenses"]
    print(
        json.dumps(
            {
                "revision": document["source"]["revision"],
                "image_id": document["artifact"]["image_id"],
                "components": summary["components"],
                "sbom_matches_image": document["artifact"]["sbom_matches_image"],
                "needs_decision": len(summary["needs_decision"]),
                "signed": document["signing"]["signed"],
                "deployed": document["deployment"]["deployed"],
            }
        )
    )
    for item in summary["needs_decision"]:
        inside = f" inside {' > '.join(item['within'])}" if item.get("within") else ""
        print(
            f"  {item['component']} {item['version']}{inside}: {item['licenses']}"
            f" ({item['reasons']})"
        )
    if document["artifact"]["sbom_matches_image"] is False:
        difference = document["artifact"]["sbom_drift"]
        print(f"SBOM does not describe the image: {json.dumps(difference)}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
