# Releases

What an ExecBound release publishes, how to check that an image is the one the project published before you run it, and how a release is made.

**No release has been published yet.** Until the first one, install from an image you build yourself, as [Install on one host](INSTALL.md) describes. Everything below describes the release workflow as it is written. That workflow first runs on the first version tag.

## What a release publishes

**The image.** It is published as `ghcr.io/execbound/execbound:<version>`, for example `:0.1.0`, and as `:<major>.<minor>`, for example `:0.1`.

- The minor line's tag moves to the newest patch of that line.
- A version's own tag never moves: the workflow refuses to push a version the registry already holds.
- There is no `latest` tag. An upgrade is a decision with a migration in it, so you name the version you are moving to.
- Images are built for `linux/amd64`.

**A GitHub Release on the tag.** Its description is the release's notes, followed by the image's digest and the command that verifies its signature. Four files are attached:

| File | What it holds |
| --- | --- |
| `sbom.cdx.json` | A CycloneDX SBOM of the Python environment the image runs from: the same locked, non-development set the image installs, synced beside it. The Rust crates compiled into `cedarpy` are listed inside its component, from the SBOM its wheel bundles. |
| `image-distributions.json` | Every Python distribution read out of the built image itself. The build fails if this and the SBOM differ in either direction, so the SBOM describes what shipped. |
| `provenance.json` | The source repository, commit and tag; the run that built it; the SHA-256 of `uv.lock`, `pyproject.toml`, the `Dockerfile` and the console's lockfile; the digest-pinned base images; the image's id; the registry digest; the signing identity; and a licence disposition that names every component whose licence is copyleft or undeclared, the crates inside `cedarpy` included. |
| `release-record.json` | What was released and from where: the tag, commit, image and digest, and the CI run that passed on the commit. It also holds the maintainer approval the release was published on, and the SHA-256 of each of the other three files. |

The licences themselves are in `THIRD_PARTY_NOTICES.md` in the repository and in the image. [Deployment](DEPLOYMENT.md#release-record-provenance-and-rollback) explains the SBOM's scope and the licence dispositions.

## Versions

- Releases are `0.x` while version 1 is being validated.
- A release tag is `v<major>.<minor>.<patch>`, with no suffix.
- The four packages the image carries share the release's version: `execbound`, `execbound-client`, `execbound-protocol` and `execbound-connectors`. The workflow refuses a tag that any of their project files or the lockfile contradicts.
- Security fixes are made in the latest release only ([Security policy](../SECURITY.md)).

### Supported versions

Only the latest release is supported. When a release is published, the one before it reaches its end of life: it gets no further fixes, security fixes included, and an installation upgrades to the new release to receive them. There is no long-term support branch for Community. Upgrades are supported from the previous minor version; going further means stepping through each minor version in order ([install on one host](INSTALL.md#support-and-versions)).

The Python client is installed from the repository with `pipx`. No package is published to PyPI.

## Verify an image before you run it

Install [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) and check the signature against the identity of the workflow that made it:

```sh
cosign verify ghcr.io/execbound/execbound:0.1.0 \
  --certificate-identity https://github.com/ExecBound/execbound/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Change both version numbers to the release you are installing.

- **The identity is the release workflow, at that tag, in this repository.** An image signed by anyone else fails, and that includes a fork, another workflow, or the same workflow at another tag. Sigstore's certificate authority issues the certificate to the workflow's GitHub token for that one run. There is no long-lived key to steal, and the signature is recorded in Sigstore's public transparency log.
- **Run the digest you verified.** The output names it. Put `ghcr.io/execbound/execbound@sha256:<digest>` in your installation's `.env` as `EXECBOUND_IMAGE`, rather than a tag, so an upgrade is always one you chose.
- **Check the attached files against the record:**

  ```sh
  sha256sum sbom.cdx.json provenance.json image-distributions.json
  ```

  The three values must match `files` in `release-record.json`. The record's `image.digest` and `provenance.json`'s `artifact.registry_digest` must match the digest cosign verified.

## How a release is made

The release workflow is `.github/workflows/release.yml`, and it runs on a pushed `v*` tag and nothing else. Its two jobs are split by what they may do.

- **`build` can only read.** It holds every step that runs third-party code: the image build, the locked environment's sync and the SBOM generator.
- **`publish` holds every write and the signing token.** It runs nothing but the runner's own `docker` and `gh`, a cosign release checked against its published SHA-256, and this repository's standard-library scripts.

The checklist, in order:

1. **The version and the notes land on `main` in a reviewed pull request.** It sets the four packages' version, updates `uv.lock`, and adds `releases/v<version>.md`, the notes, written from the changes merged since the last release. Like every change, it reaches this repository's `main` in an export pull request.
2. **CI passes on that commit's push to `main`.**
3. **A maintainer pushes the tag** `v<version>` on that commit.
4. **`build` checks the release before it builds anything** (`scripts/release_preflight.py check`). It refuses:
   - a tag that is not a release version or does not point at the commit;
   - a package version that is not the tag's;
   - missing or empty notes;
   - a commit that is not on `main`;
   - an image name, the repository variable `RELEASE_IMAGE`, that is not on `ghcr.io` or carries a tag or a digest;
   - a commit on which `ci.yml` has not passed for a push to `main`.

   It then builds and smoke-tests the image and writes the SBOM, the distributions and the provenance. It fails if the SBOM does not describe the image.
5. **A maintainer approves the run** in the `release` environment, after reading `build`'s log. This approval is the publication gate. Nothing is pushed without it, and the release record names who gave it.
6. **`publish` publishes.** It:
   - refuses unless the run carries that approval, even where the environment has lost its protection rule;
   - loads the image `build` saved and refuses unless it is the image the provenance describes;
   - refuses a version the registry already holds;
   - pushes the version and its minor line, and reads back the one digest both tags resolve to;
   - signs that digest, never a tag, and verifies the signature against the workflow's own identity;
   - records the digest and the signature in `provenance.json`, writes the release record and the notes, and publishes the GitHub Release with the four files.
7. **The release is checked from what was published.** A maintainer verifies the signature as above, installs from the published digest by [Install on one host](INSTALL.md) and upgrades an installation of the previous release by its upgrade section. The result is recorded on the release.

### If a release stops part-way

- **Before `publish` pushed anything,** nothing was published. Re-run the failed job if the cause was transient. If the code has to change, release the next patch: a tag is never moved.
- **After the push and before the GitHub Release,** the version is in the registry without the signature or record its users expect. Delete that package version, then release the next patch. A version number then only ever names a signed image with its record.

## What this does not cover

- A deployment. A release is an image and its evidence. Where it runs, who approved that, and how to roll it back are the operator's record: [Deployment](DEPLOYMENT.md#what-a-release-and-a-rollback-would-have-to-record) lists what that record has to hold.
- A server package on PyPI, Helm charts or Kubernetes manifests.
