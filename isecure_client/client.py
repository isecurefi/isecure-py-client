"""
Core ISECure client implementation.
"""

import base64
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Protocol, cast

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .error_strings import ErrorCategory, categorize_error, is_retryable_verification_error


class LogLevel(Enum):
    ERROR = "error"
    WARN = "warn"
    INFO = "info"
    DEBUG = "debug"


class Mode(Enum):
    ADMIN = "admin"
    DATA = "data"


class UserInteractionHandler(Protocol):
    """Protocol for handling user interactions like prompting for input."""

    def prompt_for_input(self, message: str) -> str:
        """
        Prompt the user for input with the given message.

        Args:
            message: The message to display to the user

        Returns:
            The user's input as a string
        """
        ...


class TerminalInteractionHandler:
    """Default implementation of UserInteractionHandler that uses terminal input."""

    def prompt_for_input(self, message: str) -> str:
        """Prompt the user for input via terminal."""
        return input(message)


@dataclass
class ISECureClient:
    """ISECureClient is a stateless client for interacting with the ISECure banking file exchange REST API."""

    company: str
    name: str
    password: str
    email: str
    mode: Mode | str
    phone: str
    public_key: str
    base_url: str
    bank: str
    api_key: str | None = None
    log_level: LogLevel | str = LogLevel.INFO
    interaction_handler: Any = None  # Type is Any to avoid forward reference issues
    max_code_retries: int = 3  # Maximum number of retries for verification codes

    # Internal state
    _access_token: str | None = field(default=None, init=False)
    _id_token: str | None = field(default=None, init=False)
    _session: str | None = field(default=None, init=False)
    _api_key: str | None = field(default=None, init=False)
    _logger: logging.Logger = field(init=False)

    def __post_init__(self) -> None:
        """Initialize the client after initialization."""
        # Convert string mode to enum if needed
        if isinstance(self.mode, str):
            self.mode = Mode(self.mode)

        # Convert string log level to enum if needed
        if isinstance(self.log_level, str):
            self.log_level = LogLevel(self.log_level)

        # Setup logging
        self._logger = logging.getLogger("ISECureClient")
        self._setup_logging()

        # Store API key in internal state
        self._api_key = self.api_key

        # Setup default interaction handler if none provided
        if self.interaction_handler is None:
            self.interaction_handler = TerminalInteractionHandler()

    def _setup_logging(self) -> None:
        """Configure the logger based on the provided log level."""
        log_level_map = {
            LogLevel.ERROR: logging.ERROR,
            LogLevel.WARN: logging.WARNING,
            LogLevel.INFO: logging.INFO,
            LogLevel.DEBUG: logging.DEBUG,
        }

        level = log_level_map.get(
            LogLevel(self.log_level) if isinstance(self.log_level, str) else self.log_level, logging.INFO
        )
        self._logger.setLevel(level)

        # Create console handler if none exists
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)

    def _pgp_url(self) -> str:
        """Get the PGP URL for the API."""
        return f"{self.base_url}/pgp"

    def _get_mode_value(self) -> str:
        """Get the mode value, handling both string and enum cases."""
        if isinstance(self.mode, str):
            return Mode(self.mode).value
        return self.mode.value

    def _get_challenge_url(self) -> str:
        """Get the challenge URL for registration."""
        return f"{self.base_url}/account/{self.email}/{self._get_mode_value()}"

    def _register_url(self) -> str:
        """Get the registration URL for the API."""
        return f"{self.base_url}/account/{self.email}/{self._get_mode_value()}"

    def _get_login_challenge_url(self) -> str:
        """Get the login challenge URL for the API."""
        return f"{self.base_url}/session/{self.email}/{self._get_mode_value()}"

    def _files_url(self) -> str:
        """Get the files URL for the API."""
        return f"{self.base_url}/files/{self.bank}"

    def _verify_phone_url(self) -> str:
        """Get the verify phone URL for the API."""
        return f"{self._register_url()}/{self.phone}"

    def _login_url(self) -> str:
        """Get the login URL for the API."""
        return self._get_login_challenge_url()

    def _login_mfa_url(self) -> str:
        """Get the login MFA URL for the API."""
        return f"{self._login_url()}/mfacode"

    def _verify_email_url(self) -> str:
        """Get the verify email URL for the API."""
        return self._register_url()

    def _get_headers(self) -> dict[str, str]:
        """Get the headers for API requests."""
        headers = {"Content-Type": "application/json"}

        if self._id_token:
            headers["Authorization"] = self._id_token

        if self._api_key:
            headers["x-api-key"] = self._api_key

        return headers

    def _retry_verification_code(
        self,
        prompt_message: str,
        request_method: Callable,
        url: str,
        prepare_data: Callable[[str], dict[str, Any]],
        handle_response: Callable[[requests.Response], None],
        verification_type: str,
    ) -> None:
        """
        Helper method to handle verification code retries.

        Args:
            prompt_message: Message to display when prompting for the code
            request_method: The request method to use (e.g., requests.post)
            url: The URL to send the request to
            prepare_data: Function that takes the code and returns request data
            handle_response: Function to handle a successful response
            verification_type: Type of verification ("MFA", "phone", "email") for logging
        """
        retries = 0
        max_retries = self.max_code_retries

        while retries <= max_retries:
            if retries > 0:
                self._logger.info(
                    f"Retrying {verification_type} verification code entry (attempt {retries}/{max_retries})"
                )

            code = self._get_user_input(prompt_message)
            data = prepare_data(code)


            try:
                response = request_method(url=url, headers=self._get_headers(), data=json.dumps(data))
                response.raise_for_status()

                # If we get here, the code was accepted
                handle_response(response)
                return  # Exit the retry loop on success

            except requests.exceptions.HTTPError as e:
                try:
                    error_response = e.response.json()
                    resp_code = error_response.get("ResponseCode")
                    resp_text = error_response.get("ResponseText", "")

                    # Check if this is a retryable verification code error
                    if resp_code == "01" and is_retryable_verification_error(resp_text):
                        # Categorize the error for proper logging
                        error_category = categorize_error(resp_text, resp_code)

                        self._logger.warning(f"Invalid verification code (category={error_category.name}): {resp_text}")

                        # Provide user-friendly feedback based on the error type
                        user_message = "Code was incorrect. Please try again."
                        if "parameter" in resp_text.lower():
                            user_message = "Code format was invalid. Please check the format and try again."

                        print(f"\n⚠️ {user_message}")

                        # Check if we've reached the max retries
                        retries += 1
                        if retries > max_retries:
                            self._logger.error(
                                f"Maximum {verification_type} verification code retry attempts ({max_retries}) exceeded"
                            )
                            # Re-raise the original error with full details
                            error_msg = str(e)
                            error_msg = f"{error_msg}\nAPI Error: {error_response}"
                            raise requests.exceptions.HTTPError(error_msg, response=e.response)

                        # If we haven't reached max retries, continue to the next loop iteration
                        continue
                    else:
                        # This is a different kind of error, we should not retry
                        self._logger.error(f"API Error Response: {error_response}")
                        error_msg = str(e)
                        error_msg = f"{error_msg}\nAPI Error: {error_response}"
                        raise requests.exceptions.HTTPError(error_msg, response=e.response)
                except (ValueError, KeyError):
                    # Could not parse error response JSON or couldn't extract error details
                    self._logger.error(f"Failed to parse error response: {e.response.text}")
                    error_msg = str(e)
                    error_msg = f"{error_msg}\nAPI Response: {e.response.text}"
                    raise requests.exceptions.HTTPError(error_msg, response=e.response)

    def _get_encrypted(self, challenge: str) -> str:
        """Encrypt password with challenge for authentication."""
        timestamp = int(challenge.split("|")[1])
        password = self.password
        pw_pair = f"{password}||{timestamp}"

        # Load public key
        key = load_pem_public_key(self.public_key.encode(), backend=default_backend())

        # Encrypt with PKCS1 OAEP padding to match RSA_PKCS1_OAEP_PADDING
        # The key will be an RSA key in this context
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

        rsa_key = cast(RSAPublicKey, key)
        encrypted_data = rsa_key.encrypt(
            pw_pair.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
        )

        # Convert to base64
        return base64.b64encode(encrypted_data).decode("utf-8")

    def _get_user_input(self, prompt: str) -> str:
        """Get user input using the interaction handler."""
        if self.interaction_handler:
            user_input = self.interaction_handler.prompt_for_input(prompt)
            return str(user_input) if user_input is not None else ""
        return input(prompt)

    def _handle_api_error(self, response: requests.Response) -> None:
        """
        Handle API errors by categorizing them and providing appropriate logging.

        Args:
            response: The error response from the API

        Raises:
            requests.exceptions.HTTPError: With appropriate error details
        """
        try:
            error_response = response.json()
            resp_code = error_response.get("ResponseCode")
            resp_text = error_response.get("ResponseText", "")

            # Categorize the error
            error_category = categorize_error(resp_text, resp_code)

            # Log based on the category
            if error_category == ErrorCategory.BANK_ERROR:
                self._logger.error(f"Bank error: {resp_text}")
            elif error_category == ErrorCategory.VERIFICATION_CODE:
                self._logger.error(f"Verification code error: {resp_text}")
            else:
                self._logger.error(f"API error: {resp_text}")

            # Include more detailed information in the exception
            error_msg = f"Error type: {error_category.name}, Code: {resp_code}, Message: {resp_text}"

            # Raise the error with the detailed message
            raise requests.exceptions.HTTPError(error_msg, response=response)

        except (ValueError, KeyError):
            # Could not parse error response JSON
            self._logger.error(f"Failed to parse error response: {response.text}")
            response.raise_for_status()  # This will raise the original error

    def update_props(self, **kwargs: Any) -> None:
        """Update client properties."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

                # Handle special case for mode
                if key == "mode" and isinstance(value, str):
                    self.mode = Mode(value)

                # Handle special case for log_level
                if key == "log_level" and isinstance(value, str):
                    self.log_level = LogLevel(value)
                    self._setup_logging()

                # Handle special case for api_key
                if key == "api_key":
                    self._api_key = value

                # No special handling needed for interaction_handler
                # as it's used directly

    def _get_reg_challenge(self) -> str:
        """Get registration challenge from the API."""
        url = self._get_challenge_url()

        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            response_data = response.json()
            challenge = response_data.get("Challenge", "")
            if not challenge:
                raise ValueError("No challenge returned from server")

            return challenge
        except requests.exceptions.HTTPError as e:
            error_msg = str(e)
            try:
                error_response = e.response.json()
                self._logger.error(f"API Error Response: {error_response}")
                error_msg = f"{error_msg}\nAPI Error: {error_response}"
            except Exception:
                self._logger.error(f"Failed to parse error response: {e.response.text}")
                error_msg = f"{error_msg}\nAPI Response: {e.response.text}"
            raise requests.exceptions.HTTPError(error_msg, response=e.response) from e

    def _get_sess_challenge(self) -> str:
        """Get session challenge from the API."""
        url = self._get_login_challenge_url()

        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            response_data = response.json()
            challenge = response_data.get("Challenge", "")
            if not challenge:
                raise ValueError("No challenge returned from server")

            return challenge
        except requests.exceptions.HTTPError as e:
            error_msg = str(e)
            try:
                error_response = e.response.json()
                self._logger.error(f"API Error Response: {error_response}")
                error_msg = f"{error_msg}\nAPI Error: {error_response}"
            except Exception:
                self._logger.error(f"Failed to parse error response: {e.response.text}")
                error_msg = f"{error_msg}\nAPI Response: {e.response.text}"
            raise requests.exceptions.HTTPError(error_msg, response=e.response) from e

    def _handle_login_response(self, response: requests.Response) -> None:
        """Handle login response and additional verification steps if needed."""
        if not response:
            self._logger.error("No response received")
            return

        data = response.json()

        # Update tokens
        self._access_token = data.get("AccessToken", self._access_token)
        self._session = data.get("Session", self._session)
        self._id_token = data.get("IdToken", self._id_token)
        self._api_key = data.get("ApiKey", self._api_key)

        resp_text = data.get("ResponseText")
        resp_code = data.get("ResponseCode")

        # Handle different response scenarios
        if resp_code == "00" and resp_text == "Give SMS code":
            self.login_mfa()

        elif resp_code == "00" and resp_text == "User authentication failed. Verify phone number with received SMS.":
            self.verify_phone()

        elif resp_code == "00" and resp_text == "Login OK. Verify email address.":
            self.verify_email()

        elif resp_code == "00" and resp_text == "Phone confirmation successful.":
            self.login()

        elif resp_code == "00" and resp_text == "Email verification successful.":
            self.login()

        elif resp_code == "01" and "LimitExceededException: Attempt limit exceeded" in resp_text:
            raise Exception(resp_text)

    def register(self) -> None:
        """Register a new user with the ISECure service."""
        challenge = self._get_reg_challenge()
        encrypted = self._get_encrypted(challenge)

        data = {
            "ApiKey": self.api_key,
            "ChResp": challenge,
            "Company": self.company,
            "Encrypted": encrypted,
            "Name": self.name,
            "Phone": self.phone,
        }

        url = self._register_url()

        try:
            response = requests.put(url=url, headers=self._get_headers(), data=json.dumps(data), timeout=30)
            response.raise_for_status()

        except requests.exceptions.HTTPError as e:
            self._handle_api_error(e.response)

    def login(self) -> None:
        """Login to the ISECure service."""
        challenge = self._get_sess_challenge()
        encrypted = self._get_encrypted(challenge)

        data = {"ChResp": challenge, "Encrypted": encrypted}

        url = self._login_url()

        try:
            response = requests.post(url=url, headers=self._get_headers(), data=json.dumps(data), timeout=30)
            response.raise_for_status()

            self._handle_login_response(response)
        except requests.exceptions.HTTPError as e:
            self._handle_api_error(e.response)

    def login_mfa(self) -> None:
        """Complete login with MFA code."""
        prompt_message = "Give the SMS login code please: "
        url = self._login_mfa_url()

        def prepare_data(code: str) -> dict[str, Any]:
            return {"Code": code, "Session": self._session}

        try:
            self._retry_verification_code(
                prompt_message=prompt_message,
                request_method=requests.put,
                url=url,
                prepare_data=prepare_data,
                handle_response=self._handle_login_response,
                verification_type="MFA",
            )
        except Exception as err:
            # Handle specific errors for MFA process
            self._logger.error(f"Error in MFA login: {err}")
            # Try to handle the error response if possible
            if hasattr(err, "response") and err.response:
                self._handle_login_response(err.response)
            else:
                raise err from None

    def verify_phone(self) -> None:
        """Verify phone number with SMS code."""
        prompt_message = "Give the SMS verification code please: "
        url = self._verify_phone_url()

        def prepare_data(code: str) -> dict[str, Any]:
            return {"Code": code}

        self._retry_verification_code(
            prompt_message=prompt_message,
            request_method=requests.post,
            url=url,
            prepare_data=prepare_data,
            handle_response=self._handle_login_response,
            verification_type="phone",
        )

    def verify_email(self) -> None:
        """Verify email with verification code."""
        if not self._access_token:
            raise Exception("No AccessToken, please call login to get AccessToken")

        prompt_message = "Give the email verification code please: "
        url = self._verify_email_url()

        def prepare_data(code: str) -> dict[str, Any]:
            return {"AccessToken": self._access_token, "Code": code}

        self._retry_verification_code(
            prompt_message=prompt_message,
            request_method=requests.post,
            url=url,
            prepare_data=prepare_data,
            handle_response=self._handle_login_response,
            verification_type="email",
        )

    def upload_pgp_key(self, armored_key: str, purpose: Literal["authorize", "export"]) -> None:
        """Upload PGP key to the service."""
        data = {"PgpKey": armored_key, "PgpKeyPurpose": purpose}

        url = self._pgp_url()

        try:
            response = requests.put(url=url, headers=self._get_headers(), data=json.dumps(data), timeout=30)
            response.raise_for_status()

        except requests.exceptions.HTTPError as e:
            self._handle_api_error(e.response)

    def upload_file(self, file_contents: str, file_name: str, file_type: str, signature: str | None = None) -> None:
        """Upload a file to the service."""
        data = {
            "FileContents": file_contents,
            "FileName": file_name,
            "FileType": file_type,
        }

        if signature:
            data["Signature"] = signature

        url = self._files_url()

        try:
            response = requests.put(url=url, headers=self._get_headers(), data=json.dumps(data), timeout=30)
            response.raise_for_status()

        except requests.exceptions.HTTPError as e:
            self._handle_api_error(e.response)

    def list_files(self, file_type: str = "", file_status: str = "") -> dict[str, Any]:
        """List files from the service."""
        query_params = ""

        if file_type or file_status:
            query_params += "?"
            if file_type:
                query_params += f"FileType={file_type}"

            if file_status and file_type:
                query_params += "&"

            if file_status:
                query_params += f"Status={file_status}"

        url = f"{self._files_url()}{query_params}"

        try:
            response = requests.get(url=url, headers=self._get_headers(), timeout=30)
            response.raise_for_status()

            status = response.status_code
            status_text = response.reason
            data = response.json()


            return {"status": status, "status_text": status_text, "data": data}
        except requests.exceptions.HTTPError as e:
            self._handle_api_error(e.response)
            # This will not execute due to the _handle_api_error raising an exception
            # but it satisfies the return type for mypy
            return {"status": 0, "status_text": "", "data": {}}
