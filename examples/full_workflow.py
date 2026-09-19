#!/usr/bin/env python3
"""
Full workflow example for ISECure Python client.
"""

import base64
import os
import sys
from pathlib import Path

# Add parent directory to path for importing isecure_client
sys.path.insert(0, str(Path(__file__).parent.parent))

from isecure_client import ISECureClient, create_pgp_signature, verify_pgp_signature


# Define a custom interaction handler
class CustomInteractionHandler:
    """Example of a custom interaction handler for ISECureClient."""

    def prompt_for_input(self, message: str) -> str:
        """
        Custom implementation to handle user prompts.
        """
        # Log the prompt for auditing
        print(f"[INTERACTION LOG] Prompt: {message}")

        # Fall back to terminal input with custom formatting
        print(f"\n[CUSTOM UI] {message}", end="")
        response = input()
        return response


def get_source_path(file_name: str) -> Path:
    """Get the path to a test file."""
    base_path = Path(__file__).parent.parent
    return base_path / file_name


def create_and_verify_pgp_signature(filename: str) -> str:
    """Create and verify a PGP signature for a test file."""
    # Read test files
    with open(Path(os.environ["ISECURE_PGP_PUBLIC_KEY_FILE"])) as f:
        public_key_armored = f.read()

    with open(Path(os.environ["ISECURE_PGP_PRIVATE_KEY_FILE"])) as f:
        private_key_armored = f.read()

    with open(get_source_path(filename)) as f:
        file_content = f.read()

    # Create signature using our PGP module
    signature = create_pgp_signature(file_content, private_key_armored, public_key_armored)
    print("Created PGP signature")

    # Verify the signature
    is_valid = verify_pgp_signature(content=file_content, signature=signature, public_key=public_key_armored)
    print(f"Signature verification: {'✅ Valid' if is_valid else '❌ Invalid'}")

    return signature


def main() -> None:
    """Main function demonstrating full workflow."""
    ## Read the public RSA key for the test environment (prod.pem for production)
    with open(get_source_path("test.pem")) as f:
        public_key = f.read()

    ## Initialize client with custom interaction handler
    custom_handler = CustomInteractionHandler()

    client = ISECureClient(
        # IMPORTANT!
        # When first time registering with ISECure, use "0" to get your API key in the login response
        # and use it for subsequent registrations, including data role!
        api_key=os.environ["ISECURE_API_KEY"],
        company=os.environ["ISECURE_COMPANY"],
        name=os.environ["ISECURE_NAME"],
        password=os.environ["ISECURE_PASSWORD"],
        phone=os.environ["ISECURE_PHONE"],
        public_key=public_key,
        base_url="https://ws-api.test.isecure.fi/v2",
        email=os.environ["ISECURE_EMAIL"],
        mode="admin",
        log_level="info",
        bank="nordea",
        interaction_handler=custom_handler,  # Use our custom handler for all user interactions
    )

    #################################################################
    ## - Registration for both Admin and Data roles
    ## - PGP key upload with Admin role
    ##

    # 1. Admin role registration
    client.register()

    # 2. Admin login
    client.login()
    print(f"Logged in ({client.mode.value})")

    # 3. Add PGP key for file upload signatures
    with open(Path(os.environ["ISECURE_PGP_PUBLIC_KEY_FILE"])) as f:
        public_key_armored = f.read()
    client.upload_pgp_key(public_key_armored, "authorize")
    print("PGP key uploaded...")

    # 3. Register data role
    client.update_props(mode="data")
    client.register()

    #################################################################
    ## File exchange with Data role
    ##

    ## 4. Login data role
    client.update_props(mode="data")
    client.login()  # Need to login to get AccessToken
    print(f"Logged in ({client.mode.value})")

    ## 5. Sign and upload file
    filename = "testfile.xml"
    detached_signature = create_and_verify_pgp_signature(filename)
    with open(get_source_path(filename)) as f:
        contents = f.read()
    client.upload_file(
        file_contents=base64.b64encode(contents.encode()).decode(),
        file_name=filename,
        file_type="DUMMY",
        signature=detached_signature,
    )

    ## 6. List files - expect this to fail on test environment
    # response = client.list_files(file_type="KTON", file_status="ALL")
    # print(response["data"])


if __name__ == "__main__":
    main()
