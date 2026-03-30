# Contributing to secure-agent-core

Thank you for your interest in contributing.

## Before You Start

By submitting a Pull Request, you agree that your contributions are licensed
under the same terms as this project (BSL 1.1, converting to Apache 2.0 on
January 1, 2030). Please confirm this in your PR description.

## How to Contribute

### Bug Reports
Open an Issue using the **Bug Report** template.  
Do NOT report security vulnerabilities publicly — see [SECURITY.md](SECURITY.md).

### Feature Requests
Open an Issue using the **Feature Request** template.  
Discuss before implementing large changes.

### Pull Requests

1. Fork the repository
2. Create a branch: `git checkout -b feat/your-feature`
3. Make your changes
4. Run tests: `python tests/test_all.py`
5. Commit with a clear message: `feat: add X` / `fix: resolve Y`
6. Open a PR against `main`

### PR Checklist

- [ ] Tests pass (`19/19`)
- [ ] New functionality has tests
- [ ] I agree my contribution is licensed under BSL 1.1 / Apache 2.0

## Development Setup

```bash
git clone https://github.com/lita-hiroto/secure-agent-core
cd secure-agent-core
pip install -e ".[dev,api]"
python tests/test_all.py
```


https://github.com/user-attachments/assets/6f7533d7-aec6-4763-a0b7-f5fc382a8e7f

