# AGENTS.md

## Core philosophy
- Shame in guessing APIs, Honor in careful research.
- Shame in vague execution, Honor in seeking confirmation.
- Shame in assuming business logic, Honor in human verification.
- Shame in creating interfaces, Honor in reusing existing ones.
- Shame in skipping validation, Honor in proactive testing.
- Shame in breaking architecture, Honor in following specifications.
- Shame in pretending to understand, Honor in honest ignorance.
- Shame in blind modification, Honor in careful refactoring.

## Dev environment tips
- Use `uv run ...` to run any command that you believe requires a specific virtual environment. If you need to install or update packages, you should also use `uv` as the package manager.
- Determine the host machine's operating system at first. Do not run Linux-only commands on Windows, nor vice versa.

## Coding style guidelines
- When introducing dependencies in your code, do not simply add the import statement in the middle of the code; instead, place it at the beginning of the file.
- Do not insert redundant comments.
- Avoid anti-patterns when coding.
- Observe the DRY principle.
- If you need to create an Alembic upgrade/downgrade script, create the framework by running the command `uv run alembic revision --autogenerate`, and then modify the parts you want to change in the generated file, instead of creating a file from scratch.

## Testing instructions
- Run tests only when necessary, as running tests will delete the original database (if SQLite is used as the database engine).
- Back up the database (`app.db`) first, if available, before running any tests.
- Use the provided MCP tools to run tests whenever possible, instead of the traditional command-line method.
- Add or update tests for the code you change, even if nobody asked.
- DO NOT run ruff by yourself since this tool is, and can only be accessed via pre-commit hooks.
