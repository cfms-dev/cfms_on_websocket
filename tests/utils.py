"""
Assertion helpers and context utilities for CFMS tests.
"""


def assert_success(response: dict, expected_code: int = 200) -> dict:
    """
    Assert that the response is successful (usually code 200).
    Returns the response data payload for easy chaining.
    """
    assert isinstance(response, dict), (
        f"Response should be a dictionary, got {type(response)}"
    )
    assert "code" in response, f"Response missing 'code': {response}"

    code = response["code"]
    msg = response.get("message", "No message")
    assert code == expected_code, (
        f"Expected code {expected_code}, got {code}. Message: {msg}\nFull response: {response}"
    )

    return response.get("data", {})


def assert_error(response: dict, expected_code: int) -> dict:
    """
    Assert that the response is an error with the expected code.
    Returns the response dictionary for further inspection if needed.
    """
    assert isinstance(response, dict), (
        f"Response should be a dictionary, got {type(response)}"
    )
    assert "code" in response, f"Response missing 'code': {response}"

    code = response["code"]
    msg = response.get("message", "No message")
    assert code == expected_code, (
        f"Expected error code {expected_code}, got {code}. Message: {msg}\nFull response: {response}"
    )

    return response
