# Python Rekor Monitor

A Python project developed for NYU CS-GY 9223: Software Supply Chain Security.

This project is based on starter code provided for Assignment 1. It implements functionality for interacting with Sigstore's Rekor transparency log, including retrieving log entries, verifying Merkle inclusion proofs, and working with checkpoint information.

## Requirements

- Python
- Poetry
- Git

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/dh2591/sscs-assignment1-sigstore-and-intoto.git
   ```

2. Open the project directory:

   ```bash
   cd sscs-assignment1-sigstore-and-intoto
   ```

3. Install dependencies:

   ```bash
   poetry install
   ```

## Usage

The program is run through `main.py`.

To view the available command-line options:

```bash
poetry run python main.py --help
```

To request verification of a Rekor inclusion proof:

```bash
poetry run python main.py --inclusion 2959795689 --artifact artifact.md
```

Replace the example log index and artifact path with the values you want to verify.

Some operations require an internet connection to access Rekor.

## Development

This project uses Poetry for dependency management.

Run Ruff to check coding style:

```bash
poetry run ruff check main.py merkle_proof.py util.py tests/
```

Run mypy for type checking:

```bash
poetry run mypy main.py merkle_proof.py util.py tests/
```

Run Bandit for security analysis:

```bash
poetry run bandit main.py merkle_proof.py util.py
```

## Testing

Automated tests are located in the `tests/` directory.

Run tests using:

```bash
poetry run python -m pytest tests/ -v
```

## Contributing

See `CONTRIBUTING.md` for contribution guidelines.

## Security

See `SECURITY.md` for instructions on reporting vulnerabilities.

## License

See the `LICENSE` file for the project's stated license. 

## Acknowledgments

The original project template was provided for NYU CS-GY 9223: Software Supply Chain Security. The missing functionality and subsequent improvements were completed as part of the course assignments.