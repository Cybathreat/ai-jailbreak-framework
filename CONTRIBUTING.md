# Contributing to AI Jailbreak Framework

⚠️ **This is a security research tool.** All contributions must align with responsible disclosure and ethical AI safety research.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/ai-jailbreak-framework.git`
3. Install in editable mode: `pip install -e ".[dev]"`
4. Run tests: `pytest tests/`

## Development Workflow

- Create a feature branch: `git checkout -b feature/your-feature`
- Make your changes
- Run tests and ensure coverage stays above 80%
- Run linting: `black . && flake8`
- Commit with a clear message
- Push and open a PR

## Code Standards

- Python 3.10+
- Type hints encouraged
- Docstrings for public APIs
- Tests for new features
- All offensive capabilities must be clearly labeled for authorized testing only

## Reporting Issues

Please include:
- Python version
- Steps to reproduce
- Expected vs actual behavior
