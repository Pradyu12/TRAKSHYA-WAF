# Contributing to TRAKSHYA-WAF

Thank you for your interest in improving TRAKSHYA-WAF.

## Ground Rules

- Be respectful. No harassment, discrimination, or toxic behavior.
- Keep issues focused. One bug or feature per issue.
- Follow the existing code style.
- Do not commit secrets, tokens, API keys, or credentials.

## Local Setup

```bash
git clone https://github.com/Pradyu12/TRAKSHYA-WAF.git
cd TRAKSHYA-WAF
python3 -m venv .venv && source .venv/bin/activate
make build
make test
```

## Commit Messages

Use clear, descriptive commit messages. Recommended format:

```
type(scope): short summary

Optional longer description.
```

Examples:
- `feat(proxy): add rate-limit burst config`
- `fix(dashboard): correct posture toggle state`
- `docs(readme): add local HTTPS dev cert notes`

Types:
- `feat` new feature
- `fix` bug fix
- `docs` documentation
- `refactor` code change that neither fixes a bug nor adds a feature
- `test` test additions or corrections
- `chore` tooling, CI, or maintenance

## Pull Request Checklist

- [ ] Tests pass: `make test`
- [ ] Lint passes: `make lint`
- [ ] Docs updated when behavior changes
- [ ] Commit history is clean and reviewable

## Reporting Bugs

Use the GitHub issue template and include reproduction steps, environment details, and logs when available.

## Security Issues

See [SECURITY.md](SECURITY.md).
