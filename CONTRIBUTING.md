# Contributing to Toride

Thank you for considering a contribution. Toride is a security library — please read
this carefully before submitting code.

---

## Core Principle (Non-Negotiable)

> **Zero LLM calls in the enforcement path.**

Any contribution that introduces a model call inside `provenance.py`, `taint.py`,
`policy.py`, or `guard.py` will be rejected. Trust decisions must be deterministic,
auditable, plain Python — never a model judging another model.

---

## Getting Started

```bash
git clone https://github.com/malrobust/TORIDE.git
cd TORIDE
pip install -e ".[dev]"
```

Run the full quality check:

```bash
ruff check .        # lint
mypy toride/        # type check
pytest              # tests
```

All three must pass before opening a pull request.

---

## How to Contribute

### Bug Reports

Open a [GitHub Issue](https://github.com/malrobust/TORIDE/issues) with:
- Python version and OS
- Minimal reproducible example
- Expected vs actual behaviour

### Feature Requests

Open an issue describing the use case first. Do not send a PR implementing a
large feature without prior discussion.

### Pull Requests

1. Fork the repo and create a branch from `main`.
2. Keep changes focused — one logical change per PR.
3. Add or update tests for any changed behaviour.
4. Run `ruff check .`, `mypy toride/`, and `pytest` before pushing.
5. Write a clear PR description explaining *why*, not just *what*.

### Adding Injection Payloads

New payloads in `toride/fuzzer.py` are welcome. They must:
- Represent a real-world prompt injection vector
- Include a descriptive `name` field
- Not duplicate an existing payload

---

## Code Style

- **Formatter**: `ruff format` (Black-compatible, 88-char lines)
- **Linter**: `ruff check` with `E`, `F`, `I`, `N` rules
- **Types**: All public functions must have type annotations; `mypy --strict` must pass

---

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add EMAIL source to fuzzer payloads
fix: handle None content_id in TaintRegistry.get
docs: clarify taint propagation in README
test: add edge case for empty source_content_ids
```

---

## License

By contributing you agree that your changes will be licensed under the [MIT License](LICENSE).
