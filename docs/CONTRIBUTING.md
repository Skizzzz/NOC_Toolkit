# Contributing to NOC Toolkit

Thank you for your interest in contributing to NOC Toolkit! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributions from everyone regardless of experience level.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Set up the development environment (see [DEVELOPMENT.md](DEVELOPMENT.md))
4. Create a new branch for your changes

```bash
git checkout -b feature/your-feature-name
```

## Development Process

### Before You Start

1. Check existing [issues](https://github.com/your-org/noc-toolkit/issues) to see if the feature or bug is already being worked on
2. For major changes, open an issue first to discuss the approach
3. Review the codebase to understand existing patterns

### Making Changes

1. Keep changes focused and atomic
2. Follow existing code style and patterns
3. Add or update tests for new functionality
4. Update documentation as needed

### Code Style

We use the following tools to maintain code quality:

```bash
# Format code
black app.py tools/

# Check linting
flake8 app.py tools/

# Type checking (optional but recommended)
mypy app.py tools/
```

Configuration is in `pyproject.toml`:
- Line length: 100 characters
- Python version: 3.11+

### Commit Messages

Write clear, concise commit messages:

```
feat: Add certificate expiration notifications

- Add email notification service
- Create notification settings page
- Schedule daily expiration checks
```

Format:
- Start with a type: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`
- Use imperative mood ("Add feature" not "Added feature")
- First line should be under 72 characters
- Include details in the body if needed

### Testing

Run the test suite before submitting:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=tools

# Run specific tests
pytest tests/test_auth.py
```

Ensure:
- All existing tests pass
- New code has test coverage
- No syntax errors: `python3 -m py_compile app.py`

## Pull Request Process

### Creating a Pull Request

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Open a Pull Request against the `main` branch

3. Fill out the PR template with:
   - Summary of changes
   - Related issue numbers
   - Testing performed
   - Screenshots (for UI changes)

### PR Requirements

- [ ] Code follows project style guidelines
- [ ] Tests pass locally
- [ ] Documentation updated (if applicable)
- [ ] Commit messages are clear
- [ ] No merge conflicts with main

### Review Process

1. Maintainers will review your PR
2. Address any requested changes
3. Once approved, a maintainer will merge your PR

## Types of Contributions

### Bug Reports

When filing a bug report, include:

- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details (Python version, OS, browser)
- Relevant logs or error messages

### Feature Requests

When suggesting a feature:

- Describe the use case
- Explain the expected behavior
- Consider security implications
- Provide mockups for UI changes (optional)

### Documentation

Documentation improvements are always welcome:

- Fix typos and clarify wording
- Add examples and explanations
- Update outdated information
- Translate documentation

### Code Contributions

Areas where help is needed:

- Bug fixes
- New features from the roadmap
- Performance improvements
- Test coverage
- Security enhancements

## Architecture Guidelines

### Backend (Python/Flask)

- Routes in `app.py` should be thin - move logic to `tools/` modules
- Use decorators for cross-cutting concerns (`@require_login`, etc.)
- Handle errors gracefully with user-friendly messages
- Log important operations for debugging

### Frontend (Jinja2/HTML)

- Extend `base.html` for consistent layout
- Use existing CSS classes and components
- Keep JavaScript minimal and in templates
- Support responsive design

### Database

- Use the functions in `tools/db_jobs.py` for database operations
- Include proper indexes for frequently queried columns
- Consider migration impacts for schema changes

### Security

- Never log passwords or sensitive data
- Use parameterized queries (already handled by db functions)
- Validate and sanitize user input
- Use `encrypt_password`/`decrypt_password` for credentials
- Apply `@require_login` to protected routes
- Apply `@require_superadmin` for admin-only routes

## Questions?

- Check existing documentation
- Search closed issues for similar questions
- Open a new issue if you need help

Thank you for contributing to NOC Toolkit!
