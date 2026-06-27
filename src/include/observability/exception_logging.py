"""
Utility functions for logging exceptions with correlation IDs.

This module provides a helper function `log_exception_with_id` that generates
a unique log ID for each exception, logs the full traceback to the provided
logger, and returns the log ID for correlation with clients. This allows for
easier debugging and tracking of errors in complex systems.
"""

import uuid

import loguru


def log_exception_with_id(
    exc: Exception,
    logger: "loguru.Logger",
    context: str | None = None,
) -> str:
    """
    Log an exception with a generated UUID4 log id and return the id.

    The full traceback will be written to the provided logger at ERROR level
    and the returned id can be shared with clients for correlation.
    """
    log_id = uuid.uuid4().hex
    if context:
        logger.opt(exception=exc).error("[{}] {}: \n", log_id, context)
    else:
        logger.opt(exception=exc).error("[{}] Error occurred: \n", log_id)
    return log_id
