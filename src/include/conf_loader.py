"""include/conf_loader.py

This module loads the global configuration from a TOML file.
It is intended to be imported by other modules to access the configuration settings.
Load the global configuration from a TOML file.

Ensure that the file is read in binary mode for compatibility with tomllib
"""

import os
import secrets
import tomllib

from tomlkit import dumps, parse

__all__ = ["global_config"]

if __name__ == "__main__":
    raise RuntimeError("This module should not be run directly.")

if not os.path.exists("config.toml"):
    raise FileNotFoundError("Configuration file 'config.toml' not found.")

if not os.path.exists("init"):
    with open("config.toml", "r", encoding="utf-8") as f:
        toml_doc = parse(f.read())

    secret_key = secrets.token_hex(32)
    pepper = secrets.token_hex(32)

    toml_doc["server"]["secret_key"] = secret_key
    toml_doc["security"]["pepper"] = pepper

    with open("config.toml", "w", encoding="utf-8") as f:
        f.write(dumps(toml_doc))

with open("config.toml", "rb") as f:
    global_config = tomllib.load(f)
