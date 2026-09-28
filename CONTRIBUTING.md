# Contributing

Thanks for helping with Postroom. Bug reports and pull requests are welcome; for larger
changes, please open an issue first to agree on the approach. Security issues go through a
private advisory instead (see [SECURITY.md](SECURITY.md)).

## Development setup

You need [uv](https://docs.astral.sh/uv/) (it installs Python 3.13 for you) and, for the
integration tests, Docker.

```sh
git clone https://github.com/vaclav-kozak/postroom.git
cd postroom
uv sync                      # creates .venv with all dev dependencies
```

Run the server locally: generate secrets into a local `.env`, then start it.

```sh
uv run postroom gen-secrets --env-out .env --password-out admin-password.txt
echo "POSTROOM_PUBLIC_URL=http://localhost:8000" >> .env
set -a; . ./.env; set +a
uv run postroom serve --host 127.0.0.1 --port 8000
```

Never commit `.env`, the password file or anything under `data/`; `.gitignore` covers them.

## Tests and lint

```sh
uv run pytest -q                    # unit tests (fast, no network)
uv run pytest -m integration -q     # integration tests: IMAP and CalDAV/CardDAV servers in Docker
uv run ruff check .
uv run ruff format .                # CI runs `ruff format --check .`
```

CI runs all of these on every pull request.

## Pull requests

- Keep each pull request focused on one change, with tests for new behaviour and bug fixes.
- Match the existing style: small modules, type hints, dataclasses; blocking IMAP work runs in
  threads; tool errors are `ToolError`s with messages safe to show to the client.
- Do not weaken the security posture (see SECURITY.md) without discussing it first, and never
  log or return secrets.
- Use `example.com`, `example.org` and `user@example.com` in tests and docs, never real
  addresses or hostnames.
- Update `.env.example` and the docs when you add a setting or change behaviour.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`,
`test:`, `refactor:`, `chore:`, `ci:`, optionally with a scope (`fix(mail): ...`). Explain
the why in the body when it is not obvious.

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
