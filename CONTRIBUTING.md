# Contributing to Advanced Threat Hunting Platform

First off, thank you for considering contributing to the Advanced Threat Hunting Platform! It's people like you that make this tool better for the entire cybersecurity community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Process](#development-process)
- [How Can I Contribute?](#how-can-i-contribute)
- [Style Guidelines](#style-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to conduct@threat-hunting-platform.dev.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Docker and Docker Compose
- Git
- PostgreSQL 14+ (or use Docker)
- Basic understanding of machine learning and cybersecurity concepts

### Setting Up Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/SCSSIP.git
   cd SCSSIP
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/SCSSIP.git
   ```

4. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

5. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

6. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your local configuration
   ```

7. **Start development services**:
   ```bash
   docker-compose up -d postgres influxdb redis
   ```

8. **Run database migrations** (when implemented):
   ```bash
   # python scripts/run_migrations.py
   ```

9. **Verify installation**:
   ```bash
   python scripts/verify_installation.py
   ```

10. **Install pre-commit hooks**:
    ```bash
    pre-commit install
    ```

### Running the Application

```bash
# Development mode with hot reload
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000

# Or using the CLI
python -m src
```

## Development Process

### Branching Strategy

We use a simplified Git Flow:

- `main`: Production-ready code
- `develop`: Integration branch for features
- `feature/*`: New features
- `bugfix/*`: Bug fixes
- `hotfix/*`: Urgent production fixes
- `docs/*`: Documentation updates

### Workflow

1. **Sync with upstream**:
   ```bash
   git checkout main
   git fetch upstream
   git merge upstream/main
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes** with regular commits

4. **Test your changes**:
   ```bash
   pytest tests/
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request** on GitHub

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title**: Descriptive summary of the issue
- **Description**: Detailed explanation of the problem
- **Steps to reproduce**: Exact steps to reproduce the behavior
- **Expected behavior**: What you expected to happen
- **Actual behavior**: What actually happened
- **Environment**: OS, Python version, deployment method
- **Logs**: Relevant error messages or logs
- **Screenshots**: If applicable

Use the bug report template when creating an issue.

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Clear title**: Descriptive summary of the enhancement
- **Motivation**: Why this enhancement would be useful
- **Detailed description**: How it should work
- **Alternatives**: Other solutions you've considered
- **Additional context**: Screenshots, mockups, or examples

### Contributing Code

#### Good First Issues

Look for issues labeled `good first issue` or `help wanted` for beginner-friendly tasks.

#### Areas for Contribution

- **New data source adapters**: Support for additional SIEM/EDR platforms
- **Machine learning models**: New anomaly detection algorithms
- **Threat hunting playbooks**: Pre-built hunting scenarios
- **Visualization dashboards**: Enhanced Grafana dashboards
- **Documentation**: Tutorials, guides, and examples
- **Testing**: Increase test coverage
- **Performance optimizations**: Speed and efficiency improvements
- **Bug fixes**: Fixing reported issues

## Style Guidelines

### Python Code Style

We follow [PEP 8](https://pep8.org/) with some modifications:

- **Line length**: 120 characters maximum
- **Formatter**: Black (configured in `pyproject.toml`)
- **Linter**: Flake8 with settings in `.flake8`
- **Type hints**: Use type hints for all function signatures
- **Docstrings**: Google-style docstrings for all public functions/classes

#### Example

```python
from typing import List, Optional
import pandas as pd


def extract_features(
    events: List[SecurityEvent],
    window_size: int = 100,
    include_network: bool = True
) -> pd.DataFrame:
    """Extract behavioral features from security events.

    Args:
        events: List of security events to process
        window_size: Number of events to process in each batch
        include_network: Whether to include network-based features

    Returns:
        DataFrame containing extracted features with columns for each feature type

    Raises:
        ValueError: If events list is empty or window_size is invalid

    Example:
        >>> events = [SecurityEvent(...), SecurityEvent(...)]
        >>> features = extract_features(events, window_size=50)
        >>> print(features.shape)
        (100, 57)
    """
    if not events:
        raise ValueError("Events list cannot be empty")

    # Implementation...
    return features_df
```

### Code Quality Tools

We use these tools (run automatically via pre-commit hooks):

- **Black**: Code formatting
- **Flake8**: Style linting
- **Mypy**: Type checking
- **Bandit**: Security linting
- **isort**: Import sorting

Run manually:
```bash
# Format code
black src/ tests/

# Check style
flake8 src/ tests/

# Type checking
mypy src/

# Security check
bandit -r src/

# Sort imports
isort src/ tests/
```

### Documentation Style

- Use **Markdown** for all documentation
- Include code examples where applicable
- Keep language clear and concise
- Use proper headings hierarchy (H1 → H2 → H3)
- Include table of contents for long documents

## Testing Guidelines

### Test Requirements

- **Unit tests**: Required for all new functions
- **Integration tests**: Required for API endpoints and data flows
- **Performance tests**: Required for critical paths
- **Minimum coverage**: 80% (target: 90%+)

### Writing Tests

```python
import pytest
from src.analytics.models import IsolationForestDetector


class TestIsolationForestDetector:
    """Test suite for Isolation Forest anomaly detector."""

    @pytest.fixture
    def detector(self):
        """Fixture providing a configured detector instance."""
        return IsolationForestDetector(contamination=0.1)

    @pytest.fixture
    def sample_data(self):
        """Fixture providing sample training data."""
        # Return sample data
        pass

    def test_training(self, detector, sample_data):
        """Test that detector can be trained successfully."""
        detector.train(sample_data)
        assert detector.is_trained()

    def test_detection_accuracy(self, detector, sample_data):
        """Test detection accuracy meets threshold."""
        detector.train(sample_data)
        predictions = detector.detect(sample_data)
        accuracy = calculate_accuracy(predictions, ground_truth)
        assert accuracy > 0.90
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/test_isolation_forest.py

# Run with specific markers
pytest -m "not slow"

# Run in parallel
pytest -n auto
```

### Test Organization

```
tests/
├── unit/               # Unit tests for individual functions/classes
├── integration/        # Integration tests for component interaction
├── performance/        # Performance and benchmark tests
├── conftest.py         # Shared fixtures
└── fixtures/           # Test data files
```

## Commit Message Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, no logic change)
- **refactor**: Code refactoring
- **perf**: Performance improvements
- **test**: Adding or updating tests
- **chore**: Build process or auxiliary tool changes
- **ci**: CI/CD changes

### Examples

```bash
feat(analytics): add LSTM-based anomaly detector

Implement LSTM neural network for time-series anomaly detection.
Achieves 96.2% accuracy on benchmark dataset.

Closes #123

---

fix(api): correct authentication token validation

Token expiration was not being checked correctly, allowing
expired tokens to be accepted.

Fixes #456

---

docs(readme): add Kubernetes deployment guide

Add comprehensive guide for deploying to K8s cluster with
Helm charts and configuration examples.
```

## Pull Request Process

### Before Submitting

1. ✅ Tests pass locally (`pytest`)
2. ✅ Code is formatted (`black`, `isort`)
3. ✅ Linting passes (`flake8`, `mypy`)
4. ✅ Security check passes (`bandit`)
5. ✅ Documentation is updated
6. ✅ CHANGELOG.md is updated (if applicable)
7. ✅ Commit messages follow guidelines

### PR Checklist

- [ ] Descriptive title following commit message format
- [ ] Description explains the changes and motivation
- [ ] Links to related issues (`Closes #123`, `Fixes #456`)
- [ ] Tests added/updated for changes
- [ ] Documentation updated
- [ ] No breaking changes (or clearly documented)
- [ ] Screenshots/videos for UI changes
- [ ] Backwards compatibility maintained

### PR Template

```markdown
## Description
Brief description of changes

## Motivation and Context
Why is this change needed? What problem does it solve?

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## How Has This Been Tested?
Describe the tests you ran and how to reproduce

## Screenshots (if applicable)

## Checklist
- [ ] My code follows the style guidelines
- [ ] I have performed a self-review
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have updated the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix/feature works
- [ ] New and existing tests pass locally
```

### Review Process

1. **Automated checks**: CI/CD pipeline runs automatically
2. **Code review**: At least one maintainer review required
3. **Feedback**: Address review comments and update PR
4. **Approval**: Maintainer approves changes
5. **Merge**: Squash and merge to target branch

### After Merge

- Pull request is merged and closed
- Branch can be deleted
- Changes appear in next release
- Credit is given in release notes

## Recognition

Contributors are recognized in:

- Release notes and CHANGELOG.md
- AUTHORS.md file
- GitHub contributors page

## Questions?

- **Documentation**: Check the [docs/](docs/) directory
- **Discussions**: Use GitHub Discussions for questions
- **Issues**: Search existing issues or create a new one
- **Email**: contribute@threat-hunting-platform.dev

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to making cybersecurity better for everyone!** 🚀

**Last Updated**: 2025-11-16
