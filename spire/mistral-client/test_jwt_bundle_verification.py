"""Regression tests for independent JWT verification with the SPIFFE SDK."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from spiffe import JwtBundle, JwtBundleSet, TrustDomain

import test_spiffe_identity as identity


class JwtBundleVerificationTests(unittest.TestCase):
    """Reject missing trust and invalid signatures instead of skipping checks."""

    def setUp(self) -> None:
        identity._failures.clear()
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.domain = TrustDomain(identity.EXPECTED_TRUST_DOMAIN)
        self.bundle = JwtBundle(self.domain, {"signing-key": self.key.public_key()})
        self.client = Mock()
        self.client.fetch_jwt_bundles.return_value = JwtBundleSet.of([self.bundle])

    def tearDown(self) -> None:
        identity._failures.clear()

    def token(self, key) -> SimpleNamespace:
        return SimpleNamespace(token=jwt.encode(
            {"sub": identity.EXPECTED_SPIFFE_ID}, key,
            algorithm="ES256", headers={"kid": "signing-key"},
        ))

    def test_sdk_bundle_verifies_signature(self) -> None:
        self.assertTrue(identity.block3_jwt_signature(self.token(self.key), self.client))

    def test_wrong_signing_key_is_rejected(self) -> None:
        other_key = ec.generate_private_key(ec.SECP256R1())
        self.assertFalse(identity.block3_jwt_signature(self.token(other_key), self.client))

    def test_missing_bundle_and_fetch_error_are_rejected(self) -> None:
        self.client.fetch_jwt_bundles.return_value = JwtBundleSet.of([])
        self.assertFalse(identity.block3_jwt_signature(self.token(self.key), self.client))
        self.client.fetch_jwt_bundles.side_effect = RuntimeError("bundle unavailable")
        self.assertFalse(identity.block3_jwt_signature(self.token(self.key), self.client))


if __name__ == "__main__":
    unittest.main()
