"""
ISECure API error categorization.
"""
import re
from enum import Enum, auto


class ErrorCategory(Enum):
    """Categories for different types of ISECure API errors."""

    VERIFICATION_CODE = auto()  # SMS or email verification code issues
    BANK_ERROR = auto()  # Bank-related errors
    API_ERROR = auto()  # General ISECure API errors


# All known ISECure API error strings with ResponseCode "01"
ISECURE_ERROR_STRINGS = [
    "All signature verification(s) failed",
    "Bank certificate(s) already exists",
    "Bank data error",
    "Can not renew cert without existing private key!",
    "Cert enrollment allowed for admin user only",
    "Cert export allowed for admin user only",
    "Cert export not yet supported.",
    "Cert import allowed for admin user only",
    "Certificate PEM format validation failed!",
    "Could not read PGP key IDs",
    "Empty bank response or error on SOAP level",
    "Failed to initialize TargetId for Nordea",
    "File downloads not allowed on admin mode, use data account mode",
    "File uploads not allowed on admin mode, use data account mode",
    "Internal server processing side error",
    "Invalid parameter bank",
    "Invalid parameter(s)",
    "Invalid signature format.",
    "Missing parameter bank",
    "Missing parameter(s)",
    "No PGP keys!",
    "No PGP keys. PGP keys are required to sign files for upload.",
    "No available bank certificates, linked account does not contain data for bank either",
    "No available bank certificates, no linked data",
    "No available valid bank certificates, no linked account",
    "No certificate(s) for this bank,",
    "No data. User may not be registered.",
    "No db data exists for user",
    "No file contents to upload",
    "No signatures found. File upload requires PGP authorize key detached signature(s).",
    "No signatures. File uploads require PGP signatures with registered PGP keys.",
    "No suitable PGP keys found.",
    "RSA Enc.Key is not private key!",
    "RSA Key is not private key!",
    "Requested export PGP key not found.",
    "Technical error. Failed to parse bank response.",
    "Technical error. No proper response body from bank.",
    "Unauthorized. Could not decode account mode from token",
    "Unauthorized. Ensure phone and email are verified.",
    "User does not exist!",
]

# Bank-related error messages
BANK_ERROR_STRINGS = [
    "Empty bank response or error on SOAP level",
    "Technical error. Failed to parse bank response.",
    "Technical error. No proper response body from bank.",
    "Bank data error",
]

# Special error messages that indicate a code verification error that can be retried
RETRYABLE_VERIFICATION_ERRORS = [
    re.compile(r"codemismatchexception", re.IGNORECASE),
    re.compile(r"invalid verification code", re.IGNORECASE),
    re.compile(r"invalid parameter\(s\): code", re.IGNORECASE),
    re.compile(r"invalid parameter\(s\): emailcode", re.IGNORECASE),
]


def categorize_error(error_message: str, response_code: str = "01") -> ErrorCategory:
    """
    Categorize an ISECure API error message.

    Args:
        error_message: The error message from the API
        response_code: The response code from the API

    Returns:
        The error category
    """
    # Only ISECure API errors have response code "01"
    if response_code != "01":
        return ErrorCategory.BANK_ERROR

    # Check if it's a bank error
    if any(bank_error in error_message for bank_error in BANK_ERROR_STRINGS):
        return ErrorCategory.BANK_ERROR

    # Check if it's a verification code error
    if any(pattern.search(error_message) for pattern in RETRYABLE_VERIFICATION_ERRORS):
        return ErrorCategory.VERIFICATION_CODE

    # All other errors are general API errors
    return ErrorCategory.API_ERROR


def is_retryable_verification_error(error_message: str) -> bool:
    """
    Check if an error message indicates a verification code error that can be retried.

    Args:
        error_message: The error message from the API

    Returns:
        True if the error is related to verification codes and can be retried
    """
    return any(pattern.search(error_message) for pattern in RETRYABLE_VERIFICATION_ERRORS)


def is_bank_error(error_message: str, response_code: str = "01") -> bool:
    """
    Check if an error message indicates a problem with the bank rather than the ISECure API.

    Args:
        error_message: The error message from the API
        response_code: The response code from the API

    Returns:
        True if the error is related to a bank issue
    """
    # Direct bank errors don't have response code "01"
    if response_code != "01":
        return True

    # Check if it's one of the known bank-related errors
    return any(bank_error in error_message for bank_error in BANK_ERROR_STRINGS)
