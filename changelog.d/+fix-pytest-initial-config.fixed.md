Initialize the isolated test runtime before pytest loads child conftest files, and clean it up even when configuration fails, fixing CI collection errors caused by a missing config.toml.
