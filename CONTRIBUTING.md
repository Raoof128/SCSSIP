# Contributing to SBOM Security Platform

Thank you for your interest in contributing! This is primarily a portfolio project, but contributions are welcome.

## Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/SCSSIP.git
   cd SCSSIP
   ```

2. **Install dependencies**
   ```bash
   poetry install
   ```

3. **Set up pre-commit hooks** (optional)
   ```bash
   poetry run pre-commit install
   ```

4. **Run tests**
   ```bash
   poetry run pytest
   ```

## Code Standards

- **Python 3.11+** with type hints
- **Black** for code formatting (line length: 100)
- **Ruff** for linting
- **pytest** for testing (>85% coverage required)
- **Docstrings** for public APIs (Google style)

## Testing

All new features must include tests:

```bash
# Run tests with coverage
poetry run pytest --cov=src

# Run specific tests
poetry run pytest tests/unit/test_cyclonedx_parser.py -v

# Check coverage
poetry run pytest --cov-report=html
```

## Pull Request Process

1. Create a feature branch: `git checkout -b feature/your-feature-name`
2. Write code with tests
3. Ensure all tests pass and coverage >85%
4. Run linters: `poetry run black . && poetry run ruff check .`
5. Commit with descriptive messages
6. Push and create a Pull Request

## Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `chore`: Maintenance

**Example:**
```
feat(parser): add support for SPDX 3.0 format

Implemented parser for SPDX 3.0 specification including:
- New schema validation
- Component extraction
- Relationship mapping

Closes #123
```

## Questions?

Open an issue or reach out to [@Raoof128](https://github.com/Raoof128)
