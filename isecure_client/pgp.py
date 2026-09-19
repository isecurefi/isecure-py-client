"""
PGP operations for ISECure client using PGPy.
"""

import os
import shutil
import tempfile
from typing import Any

import pgpy
from pgpy.constants import HashAlgorithm, SignatureType


class GPGError(Exception):
    """Exception raised for errors in the PGP operations."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        """
        Initialize with error details.

        Args:
            message: The error message
            details: Additional details about the error
        """
        self.details = details or {}
        super().__init__(message)


class PGPHandler:
    """A handler for PGP operations using the PGPy library."""

    def __init__(self) -> None:
        """Initialize the PGP handler with a secure temporary directory."""
        # Create a temporary directory with secure permissions
        self.tempdir = tempfile.mkdtemp(prefix="isecure_pgp_")
        os.chmod(self.tempdir, 0o700)  # Secure permissions

        # Store loaded keys
        self.public_keys: dict[str, pgpy.PGPKey] = {}
        self.private_keys: dict[str, pgpy.PGPKey] = {}

    def _cleanup(self) -> None:
        """Clean up the temporary directory."""
        if hasattr(self, "tempdir") and os.path.exists(self.tempdir):
            shutil.rmtree(self.tempdir, ignore_errors=True)

    def __del__(self) -> None:
        """Clean up the temporary directory on destruction."""
        self._cleanup()

    def import_keys(self, public_key: str, private_key: str | None = None) -> tuple[str, str | None]:
        """
        Import the PGP keys.

        Args:
            public_key: The PGP public key in armored format
            private_key: Optional PGP private key in armored format

        Returns:
            Tuple containing the fingerprints of the imported public and private keys

        Raises:
            GPGError: If key import fails
        """
        # Import public key
        try:
            pub_key, _ = pgpy.PGPKey.from_blob(public_key)
            if not pub_key:
                raise GPGError("Failed to import PGP public key - invalid format")

            pub_fingerprint = pub_key.fingerprint
            self.public_keys[pub_fingerprint] = pub_key

        except Exception as e:
            raise GPGError(f"Failed to import PGP public key: {str(e)}") from e

        # Import private key if provided
        priv_fingerprint = None
        if private_key:
            try:
                priv_key, _ = pgpy.PGPKey.from_blob(private_key)
                if not priv_key:
                    raise GPGError("Failed to import PGP private key - invalid format")

                if not priv_key.is_protected and not priv_key.is_unlocked:
                    # We need a private key, not just a public key
                    raise GPGError("Provided private key doesn't contain private key material")

                priv_fingerprint = priv_key.fingerprint
                self.private_keys[priv_fingerprint] = priv_key

            except Exception as e:
                raise GPGError(f"Failed to import PGP private key: {str(e)}") from e

        return pub_fingerprint, priv_fingerprint

    def sign(self, key_fingerprint: str, content: str, passphrase: str | None = None) -> str:
        """
        Create a detached PGP signature for content.

        Args:
            key_fingerprint: The fingerprint of the private key to use for signing
            content: The content to sign
            passphrase: Optional passphrase for the private key

        Returns:
            The detached signature in ASCII-armored format

        Raises:
            GPGError: If signature creation fails
        """
        # Check if key exists and get it
        if key_fingerprint not in self.private_keys:
            raise GPGError(
                f"Private key with fingerprint {key_fingerprint} not found",
                details={"available_keys": list(self.private_keys.keys())},
            )

        private_key = self.private_keys[key_fingerprint]

        # Unlock the key if it's protected and passphrase is provided
        if private_key.is_protected and not private_key.is_unlocked:
            if passphrase is None:
                raise GPGError("Passphrase required for protected key")
            try:
                with private_key.unlock(passphrase) as unlocked_key:
                    signature = unlocked_key.sign(
                        content.encode("utf-8"),
                        hash_algorithm=HashAlgorithm.SHA256,
                        signature_type=SignatureType.BinaryDocument,
                    )
            except Exception as e:
                raise GPGError(f"Failed to unlock key: {str(e)}") from e
        else:
            # Not protected or already unlocked
            try:
                if private_key.is_protected and not private_key._key.is_unlocked:
                    # Handle the rare case where is_unlocked doesn't match the internal state
                    if passphrase is None:
                        raise GPGError("Passphrase required for protected key")
                    with private_key.unlock(passphrase):
                        signature = private_key.sign(
                            content.encode("utf-8"),
                            hash_algorithm=HashAlgorithm.SHA256,
                            signature_type=SignatureType.BinaryDocument,
                        )
                else:
                    # Directly sign with the key
                    signature = private_key.sign(
                        content.encode("utf-8"),
                        hash_algorithm=HashAlgorithm.SHA256,
                        signature_type=SignatureType.BinaryDocument,
                    )
            except Exception as e:
                raise GPGError(f"Failed to create signature: {str(e)}") from e

        return str(signature)

    def verify(self, content: str, signature: str) -> bool:
        """
        Verify a detached PGP signature.

        Args:
            content: The original content
            signature: The detached signature to verify

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Parse the signature
            sig = pgpy.PGPSignature.from_blob(signature)

            # Try to verify with each available public key
            for fingerprint, key in self.public_keys.items():
                try:
                    # Check if the key has expired and reset it temporarily for verification
                    original_expires = key.expires_at
                    key.expires_at = None  # Temporarily disable key expiration

                    result = key.verify(content.encode("utf-8"), sig)

                    # Restore original expiration
                    key.expires_at = original_expires

                    if result:
                        return True
                except Exception as e:
                    # Log the exception for debugging
                    import logging

                    logging.debug(f"Verification with key {fingerprint} failed: {str(e)}")
                    # This key didn't work, try the next one
                    continue

            # If we get here, none of the keys could verify the signature
            return False

        except Exception as e:
            # Log the exception for debugging
            import logging

            logging.debug(f"Signature verification failed: {str(e)}")
            # Any parsing errors, invalid signature format, etc.
            return False


# Module-level convenience functions for simpler usage
def create_pgp_signature(
    content: str,
    private_key: str,
    public_key: str | None = None,
    passphrase: str | None = None,
) -> str:
    """
    Create a PGP signature for content using the specified private key.

    Args:
        content: The content to sign
        private_key: The PGP private key in armored format
        public_key: The PGP public key in armored format (optional but recommended)
        passphrase: Optional passphrase for the private key

    Returns:
        The detached signature in ASCII-armored format

    Raises:
        GPGError: If any PGP operation fails
    """
    handler = PGPHandler()

    try:
        # Import keys
        pub_fingerprint = None
        priv_fingerprint = None

        if public_key:
            # Import both keys
            pub_fingerprint, priv_fingerprint = handler.import_keys(public_key, private_key)
            if not priv_fingerprint:
                # Try to import private key separately
                priv_key, _ = pgpy.PGPKey.from_blob(private_key)
                priv_fingerprint = priv_key.fingerprint
                if priv_fingerprint:  # Ensure fingerprint is not None
                    handler.private_keys[priv_fingerprint] = priv_key
        else:
            # Import just the private key (it should include the public part)
            priv_key, _ = pgpy.PGPKey.from_blob(private_key)
            priv_fingerprint = priv_key.fingerprint
            if priv_fingerprint:  # Ensure fingerprint is not None
                handler.private_keys[priv_fingerprint] = priv_key

            # Extract public key from private key and add it to public keys
            # This is needed for verification to work in the private-key-only case
            pub_key = priv_key.pubkey
            pub_fingerprint = pub_key.fingerprint
            if pub_fingerprint:  # Ensure fingerprint is not None
                handler.public_keys[pub_fingerprint] = pub_key

        if not priv_fingerprint:
            raise GPGError("Failed to identify the private key fingerprint")

        # Create signature
        return handler.sign(priv_fingerprint, content, passphrase)
    except GPGError:
        # Re-raise GPGError unchanged
        raise
    except Exception as e:
        # Convert other exceptions to GPGError
        raise GPGError(f"Unexpected error during PGP signature creation: {str(e)}") from e


def verify_pgp_signature(content: str, signature: str, public_key: str) -> bool:
    """
    Verify a PGP signature using the specified public key.

    Args:
        content: The original content
        signature: The detached signature to verify
        public_key: The PGP public key in armored format

    Returns:
        True if signature is valid, False otherwise

    Raises:
        GPGError: If any PGP operation fails
    """
    try:
        handler = PGPHandler()

        # Import public key
        pub_key, _ = pgpy.PGPKey.from_blob(public_key)
        pub_fingerprint = pub_key.fingerprint
        handler.public_keys[pub_fingerprint] = pub_key

        # Parse the signature
        sig = pgpy.PGPSignature.from_blob(signature)

        try:
            # Try direct verification
            result = pub_key.verify(content.encode("utf-8"), sig)
            return bool(result)
        except Exception as e:
            # Fall back to handler.verify if direct verification fails
            import logging

            logging.debug(f"Direct verification failed, falling back to handler.verify: {str(e)}")
            return handler.verify(content, signature)

    except GPGError:
        # Re-raise GPGError unchanged
        raise
    except Exception as e:
        # Convert other exceptions to GPGError
        import logging

        logging.debug(f"PGP verification failed: {str(e)}")
        raise GPGError(f"Unexpected error during PGP signature verification: {str(e)}") from e
