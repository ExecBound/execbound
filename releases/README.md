# Release notes

One file per release, `v<major>.<minor>.<patch>.md`. Each is written before its tag is pushed, and reviewed in the pull request that carries it. The release workflow refuses a tag whose notes file is missing or empty. It publishes the file as the GitHub Release's description, followed by the image's digest and the command that verifies its signature.

Write the notes from the changes merged since the previous release. For someone running ExecBound, say:

- what changed;
- what an upgrade needs: a migration, a configuration change, a command to run;
- what the release still does not do.

[Releases](../docs/RELEASE.md) is the whole checklist.
