# The Community bundle

The files an installation is made of now live **inside the image**, under
`src/execbound/data/community/`: the compose file, the script that creates the restricted runtime
role on an empty data directory, and the starter ruleset. `execbound init <dir>` copies them out
beside the `.env` and the private material it generates, because somebody installing ExecBound has
the image and no repository, and one copy of a file cannot drift from another.

**Read [`docs/INSTALL.md`](../../docs/INSTALL.md).** Three commands, from a machine with Docker and
nothing else to a governed decision:

```sh
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/execbound:/install" execbound:community execbound init /install
cd execbound && docker compose up -d
docker compose run --rm gateway execbound quickstart
```

Two things in the compose file that look odd and are not:

**Every process shares one network namespace, held by a container that runs nothing.**
`ConnectionConfig` refuses a cleartext origin whose host is not a loopback IP, and `connection.py`
refuses a PostgreSQL URL whose host is not loopback without `sslmode=verify-full` and a CA bundle, so
`http://endpoint:8000` and `db:5432` over an ordinary compose network are both refused at startup.
Sharing the namespace makes them genuinely reachable at `127.0.0.1`, which is the condition those
rules are about. A provider or a database on another host serves HTTPS, and that is a deployment
rather than a quickstart. The namespace belongs to `netns`, which runs `sleep`, and not to the
database: a container that joined a namespace stays in it when the owner restarts, so while the
database owned it, every restart of the database left the others where nobody could reach them.

**The provider store and the credential files are bind-mounted directories, not named volumes.** A
named volume is created root-owned, and these processes deliberately run as the installer rather than
as root, so neither could ever be written. Backing the store up matters either way: a provider that
loses its SQLite store loses the journals that settle retained uncertainty, so an uncertain operation
would have nothing to be reconciled from.
