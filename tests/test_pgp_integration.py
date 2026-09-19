"""
Integration tests for PGP operations that use real GPG instead of mocks.
"""
import unittest

from pgpy import PGPUID, PGPKey
from pgpy.constants import CompressionAlgorithm, HashAlgorithm, KeyFlags, PubKeyAlgorithm, SymmetricKeyAlgorithm

# Import directly from our module
from isecure_client.pgp import create_pgp_signature, verify_pgp_signature


class TestPGPIntegration(unittest.TestCase):
    """Integration tests for PGP operations that use real GPG."""

    test_content = "Please sign me"
    SAMPLE_PUBLIC_KEY: str
    SAMPLE_PRIVATE_KEY: str

    @classmethod
    def setUpClass(cls) -> None:
        """Generate disposable keys locally; never publish reusable private keys."""
        key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
        key.add_uid(
            PGPUID.new("SDK test", email="sdk-test@example.invalid"),
            usage={KeyFlags.Sign},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.Uncompressed],
        )
        cls.SAMPLE_PUBLIC_KEY = str(key.pubkey)
        cls.SAMPLE_PRIVATE_KEY = str(key)

    def test_private_key_only_signature(self) -> None:
        """Test that signing works with only private key (public part is extracted)."""
        # Sign with only private key
        signature = create_pgp_signature(
            content=self.test_content,
            private_key=self.SAMPLE_PRIVATE_KEY,
            # No public key provided
        )

        self.assertIsNotNone(signature)
        self.assertIn("BEGIN PGP SIGNATURE", signature)

        # Verify the signature
        is_valid = verify_pgp_signature(
            content=self.test_content, signature=signature, public_key=self.SAMPLE_PUBLIC_KEY
        )
        self.assertTrue(is_valid)

    def test_signature_validation_fails_with_modified_content(self) -> None:
        """Test that signature validation fails when content is modified."""
        # Create a signature for the original content
        signature = create_pgp_signature(
            content=self.test_content,
            private_key=self.SAMPLE_PRIVATE_KEY,
            public_key=self.SAMPLE_PUBLIC_KEY,
        )

        # Modify the content
        modified_content = self.test_content + " Some additional text to invalidate signature"

        # Verify should fail with modified content
        is_valid = verify_pgp_signature(
            content=modified_content, signature=signature, public_key=self.SAMPLE_PUBLIC_KEY
        )
        self.assertFalse(is_valid)

    def test_public_private_key_signature(self) -> None:
        """Test signing with both public and private keys."""
        # Sign with both keys
        signature = create_pgp_signature(
            content=self.test_content,
            private_key=self.SAMPLE_PRIVATE_KEY,
            public_key=self.SAMPLE_PUBLIC_KEY,
        )

        self.assertIsNotNone(signature)
        self.assertIn("BEGIN PGP SIGNATURE", signature)

        # Verify the signature
        is_valid = verify_pgp_signature(
            content=self.test_content, signature=signature, public_key=self.SAMPLE_PUBLIC_KEY
        )
        self.assertTrue(is_valid)


if __name__ == "__main__":
    unittest.main()
