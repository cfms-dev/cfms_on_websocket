# AGENTS.md

## Dev environment tips
- Use `uv run ...` to run any command that you believe requires a specific virtual environment. If you need to install or update packages, you should also use `uv` as the package manager.
- Determine the host machine's operating system at first. Do not run Linux-only commands on Windows, nor vice versa.

## Coding style guidelines
- When introducing dependencies in your code, do not simply add the import statement in the middle of the code; instead, place it at the beginning of the file.

## Testing instructions
- Run tests only when necessary, as running tests will delete the original database (if SQLite is used as the database engine).
- Back up the database (`app.db`) first, if available, before running any tests.
- Use the provided MCP tools to run tests whenever possible, instead of the traditional command-line method.
- Add or update tests for the code you change, even if nobody asked.
