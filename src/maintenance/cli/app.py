import typer

from maintenance.cli import (
    audit,
    backup,
    config,
    database,
    deployment,
    extensions,
    permissions,
    users,
)

app = typer.Typer(
    help="CFMS maintenance command line tools.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
app.add_typer(users.app, name="user")
app.add_typer(config.app, name="config")
app.add_typer(backup.app, name="backup")
app.add_typer(audit.app, name="audit")
app.add_typer(permissions.app, name="permission")
app.add_typer(database.app, name="database")
app.add_typer(deployment.app, name="deployment")
app.add_typer(extensions.app, name="extension")


if __name__ == "__main__":
    app()
