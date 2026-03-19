# Contributing to SYCTF

Thanks for helping improve SYCTF.

## Quick Start

1. Fork the repository.
2. Create a branch from `main`.
3. Set up a virtual environment.
4. Install dependencies.
5. Make your changes with tests.
6. Open a pull request.

## Local Setup

```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Development Guidelines

- Keep changes focused and small.
- Add or update tests for behavior changes.
- Keep command output clear for beginners.
- Avoid introducing unsafe defaults in security tooling.

## Pull Request Checklist

- [ ] Code runs locally (`python -m syctf --help`)
- [ ] Relevant tests pass
- [ ] Documentation is updated if needed
- [ ] No secrets, local paths, or generated artifacts included

## Code of Conduct

By participating, you agree to follow the project's code of conduct.
