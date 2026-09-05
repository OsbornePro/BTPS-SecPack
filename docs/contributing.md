# Contributing

Contributions, fixes, and documentation improvements are welcome. The canonical contribution instructions live in the repository's [CONTRIBUTING.md](https://github.com/OsbornePro/BTPS-SecPack/blob/master/CONTRIBUTING.md).

## Documentation changes

The Read the Docs site is built with Sphinx, MyST Markdown, and the Furo theme. To preview it locally:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r docs\requirements.txt
sphinx-build -W --keep-going -b html docs docs\_build\html
```

On Linux or macOS, activate the virtual environment with `source .venv/bin/activate` and use forward slashes in paths.

When editing docs, keep instructions aligned with the actual repository, avoid embedding secrets or organization-specific credentials, and call out commands that make system-level changes.

## Repository standards

Before submitting code, review the project's `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, `DISCLAIMER.md`, and `LICENSE` in the repository root.
