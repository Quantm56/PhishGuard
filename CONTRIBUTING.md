# Contributing to PhishGuard

Thank you for your interest in contributing to **PhishGuard**! We welcome contributions, bug reports, feature requests, and improvements.

## Code of Conduct

Please be respectful and constructive in all discussions, issues, and pull requests.

## How to Contribute

### 1. Reporting Bugs
- Check the [Issues](https://github.com/Quantm56/PhishGuard/issues) tab to see if the issue has already been reported.
- If not, open a new issue describing:
  - Expected behavior vs. actual behavior
  - Reproducible sample URL or code snippet
  - OS and Python version
  - Relevant logs or stack traces

### 2. Suggesting Features
- Open an issue describing the proposed feature or improvement (e.g., additional threat intelligence feed integrations, new heuristic rules, or model architectures).

### 3. Submitting Pull Requests
1. Fork the repository.
2. Create a new branch: `git checkout -b feature/your-feature-name`.
3. Set up a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate

   pip install -r requirements.txt
   ```
4. Implement your changes and write unit tests in `tests/test_pipeline.py`.
5. Run unit tests to verify:
   ```bash
   python -m unittest discover -s tests -v
   ```
6. Commit your changes with clear messages and push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```
7. Open a Pull Request against the `main` branch.

## License

By contributing to PhishGuard, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
