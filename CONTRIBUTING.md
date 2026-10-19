# Contributing Guidelines

## Reporting Issues

If you find a bug or want to suggest an improvement, create a GitHub issue.

Please include:
- A clear description of the problem.
- Steps to reproduce the issue.
- The expected and actual behavior.
- Relevant error messages or screenshots.

Do not include passwords, API keys, or other sensitive information in public issues.

## Submitting Pull Requests

1. Create a new branch for your changes.
2. Make your changes and add appropriate tests.
3. Run the project's automated checks.
4. Commit your changes with a descriptive commit message.
5. Open a pull request targeting the `main` branch.
6. Describe your changes and link any related GitHub issues.

Changes should be reviewed before being merged into `main`.

## Coding Style

Follow Python PEP 8 coding conventions.

Use Ruff to check coding style:

```bash
poetry run ruff check .
```

Use clear function and variable names, and include comments where they improve readability.

## Testing Requirements

Install project dependencies using:

```bash
poetry install
```

Run automated tests before submitting a pull request:

```bash
poetry run pytest
```

Run type checking:

```bash
poetry run mypy main.py merkle_proof.py util.py
```

Run security analysis:

```bash
poetry run bandit main.py merkle_proof.py util.py
```

All tests and required checks should pass before changes are merged.

## Security

Never commit secrets or credentials.

Report suspected security vulnerabilities privately according to the instructions in `SECURITY.md`.