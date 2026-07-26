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
- Prefer standard-library abstractions and existing project facilities over custom interfaces, wrappers, or utilities when they satisfy the required semantics; introduce new abstractions only when existing ones do not fit.
- When introducing dependencies in your code, do not simply add the import statement in the middle of the code; instead, place it at the beginning of the file.
- Combine nested context managers with the same lifetime into a single `with` statement.
- Do not define a separate function that merely wraps or forwards to a single operation without adding reusable domain semantics, validation, state management, or meaningful composition; inline the operation at its call site.
- Use `datetime.datetime.now(datetime.UTC).date()` instead of `datetime.date.today()` so the current date has an explicit timezone basis.
- Use the `datetime.UTC` alias (or the corresponding module alias, such as `dt.UTC`) instead of `datetime.timezone.utc`.
- Do not insert redundant comments.
- Avoid anti-patterns when coding.
- Observe the DRY principle.
- If you need to create an Alembic upgrade/downgrade script, create the framework by running the command `uv run alembic revision --autogenerate`, and then modify the parts you want to change in the generated file, instead of creating a file from scratch.

## Commit conventions
- When the required changes are substantial, commit them in stages where appropriate to avoid difficulties during subsequent reviews.
- Clearly specify the contents of this submission, ensuring no necessary information is omitted.

## Testing instructions
- Run tests only when necessary, as running tests will delete the original database (if SQLite is used as the database engine).
- Back up the database (`app.db`) first, if available, before running any tests.
- Use the provided MCP tools to run tests whenever possible, instead of the traditional command-line method.
- Add or update tests for the code you change, even if nobody asked.
- DO NOT run ruff by yourself since this tool is, and can only be accessed via pre-commit hooks.
