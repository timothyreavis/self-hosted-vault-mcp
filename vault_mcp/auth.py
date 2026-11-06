"""Cloudflare Access assertion boundary. The OAuth bearer is opaque to this origin."""
import contextvars
import re
from dataclasses import dataclass

import jwt


principal_var = contextvars.ContextVar("principal")


@dataclass(frozen=True)
class Principal:
    identity: str
    scopes: frozenset[str]

    def require(self, scope: str) -> None:
        if scope not in self.scopes:
            raise PermissionError("capability denied")


class AccessVerifier:
    def __init__(self, team: str, audience: str, users: dict[str, frozenset[str]], services: dict[str, frozenset[str]]):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", team) or not audience.strip() or audience != audience.strip() or not (users or services):
            raise ValueError("Access configuration is incomplete")
        self.issuer = f"https://{team}.cloudflareaccess.com"
        self.audience = audience
        self.users = users
        self.services = services
        self.keys = jwt.PyJWKClient(f"{self.issuer}/cdn-cgi/access/certs", timeout=5, lifespan=300)

    def verify(self, assertion: str) -> Principal:
        key = self.keys.get_signing_key_from_jwt(assertion)
        claims = jwt.decode(assertion, key.key, algorithms=["RS256"], audience=self.audience,
                            issuer=self.issuer, options={"require": ["exp", "iat", "iss", "aud"]}, leeway=0)
        email = claims.get("email")
        client = claims.get("common_name")
        if client is not None:
            if isinstance(client, str) and client in self.services:
                return Principal(f"service:{client}", self.services[client])
            raise PermissionError("principal denied")
        if isinstance(email, str) and email.lower() in self.users:
            return Principal(f"user:{email.lower()}", self.users[email.lower()])
        raise PermissionError("principal denied")


class AccessASGI:
    def __init__(self, app, verifier: AccessVerifier):
        self.app, self.verifier = app, verifier

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        values = [v for k, v in scope["headers"] if k.lower() == b"cf-access-jwt-assertion"]
        try:
            if len(values) != 1:
                raise PermissionError("one Access assertion required")
            principal = self.verifier.verify(values[0].decode("ascii"))
        except (ValueError, TypeError, OverflowError, UnicodeError, PermissionError, jwt.PyJWTError, OSError):
            await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"text/plain")]})
            await send({"type": "http.response.body", "body": b"Unauthorized"})
            return
        token = principal_var.set(principal)
        try:
            await self.app(scope, receive, send)
        finally:
            principal_var.reset(token)


def principal() -> Principal:
    return principal_var.get()
