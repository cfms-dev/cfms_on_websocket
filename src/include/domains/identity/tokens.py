__all__ = ["Token"]

import time

import jwt


class Token:
    def __init__(
        self,
        secret: str,
        username: str | None = None,
        raw_token: str | None = None,
    ):
        self._raw = None

        self.exp = None
        self.username = username
        self.secret = secret

        # Invoke raw.setter.
        self.raw = raw_token

    @property
    def raw(self):
        return self._raw

    @raw.setter
    def raw(self, raw_token):
        self._raw = raw_token
        if not raw_token:
            self.exp = None
            return

        # Decode the token.
        decoded = jwt.decode(self._raw, self.secret, algorithms="HS256")
        if self.username:  # Avoid presetting username before assigning raw_token.
            if decoded.get("username") != self.username:
                raise ValueError("New token does not belong to the assigned user")
        else:
            self.username = decoded.get("username")
        self.exp = decoded.get("exp")

    @property
    def is_valid(self):
        if not self._raw:
            return False
        now = time.time()
        return now < self.exp if self.exp else True

    def new(self, duration: float):
        payload = {"username": self.username, "exp": time.time() + duration}
        self._raw = jwt.encode(payload, self.secret, algorithm="HS256")
        self.exp = payload["exp"]
