## What and why

<!-- What does this change, and why? Link the issue: Fixes #123 -->

## How it was tested

<!-- Unit tests, integration tests, manual steps. -->

## Checklist

- [ ] `uv run ruff check . && uv run ruff format --check .` passes
- [ ] `uv run pytest -q` passes (and `uv run pytest -m integration -q` if mail/DAV code changed)
- [ ] New behaviour is covered by tests
- [ ] No secrets, real email addresses or personal hostnames in code, tests or docs
      (use `example.com` / `user@example.com`)
- [ ] Security posture unchanged or improved (owner-only admin, OAuth redirect allow-list,
      encrypted secrets, IMAP injection guard, memory bounds); explain any change below
- [ ] Docs / `.env.example` updated for new settings or behaviour
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
