import asyncio
import time
import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from vault_mcp.auth import AccessASGI, AccessVerifier, principal


class AccessFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.verifier = AccessVerifier("fixture", "app-audience", {"owner@example.invalid": frozenset({"read", "agent_write"})},
                                       {"bot-client": frozenset({"read"})})
        self.verifier.keys.get_signing_key_from_jwt = lambda _: type("Key", (), {"key": self.key.public_key()})()

    def assertion(self, **overrides):
        claims = {"iss": "https://fixture.cloudflareaccess.com", "aud": "app-audience", "iat": int(time.time()),
                  "exp": int(time.time()) + 60, "email": "owner@example.invalid"}
        claims.update(overrides)
        return jwt.encode(claims, self.key, algorithm="RS256")

    def test_user_service_and_denials(self):
        self.assertEqual(self.verifier.verify(self.assertion()).identity, "user:owner@example.invalid")
        self.assertEqual(self.verifier.verify(self.assertion(email=None, common_name="bot-client")).scopes, frozenset({"read"}))
        for claims in ({"exp": int(time.time()) - 1}, {"iss": "https://wrong.invalid"},
                       {"aud": "wrong"}, {"email": "other@example.invalid"}):
            with self.assertRaises((jwt.PyJWTError, PermissionError)):
                self.verifier.verify(self.assertion(**claims))

    def test_http_missing_and_duplicate_assertions(self):
        async def inner(scope, receive, send):
            self.assertEqual(principal().identity, "user:owner@example.invalid")
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})
        async def request(headers):
            events = []
            async def send(event):
                events.append(event)
            await AccessASGI(inner, self.verifier)({"type": "http", "headers": headers}, None, send)
            return events[0]["status"]
        token = self.assertion().encode()
        header = (b"cf-access-jwt-assertion", token)
        self.assertEqual(asyncio.run(request([])), 401)
        self.assertEqual(asyncio.run(request([header, header])), 401)
        self.assertEqual(asyncio.run(request([header])), 200)

    def test_forgery_missing_claims_and_service_not_user_fallback(self):
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        bad = jwt.encode({"iss": self.verifier.issuer, "aud": self.verifier.audience,
                          "iat": int(time.time()), "exp": int(time.time())+60,
                          "email": "owner@example.invalid"}, other_key, algorithm="RS256")
        for token in ("invalid", bad, self.assertion(common_name="unknown-service"),
                      self.assertion(exp=None), self.assertion(aud=None),
                      self.assertion(iat=int(time.time())+100)):
            with self.assertRaises((jwt.PyJWTError, PermissionError, TypeError)):
                self.verifier.verify(token)

    def test_concurrent_context_reset(self):
        async def exercise():
            async def inner(scope, receive, send):
                before = principal()
                await asyncio.sleep(0)
                self.assertEqual(principal(), before)
                await send({"type": "http.response.start", "status": 200, "headers": []})
            app = AccessASGI(inner, self.verifier)
            async def request(assertion):
                async def send(event):
                    pass
                await app({"type": "http", "headers": [(b"cf-access-jwt-assertion", assertion.encode())]}, None, send)
                with self.assertRaises(LookupError):
                    principal()
            await asyncio.gather(request(self.assertion()), request(self.assertion(email=None, common_name="bot-client")))
        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
