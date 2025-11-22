# src/ocpp_anonymizer/hasher.py

import hashlib
from urllib.parse import urlparse, urlunparse

import os
import warnings

# CRITICAL: This salt is used to ensure deterministic (consistent) hashing.
# It is recommended to set this as an environment variable.
DEFAULT_SALT = "YOUR_SUPER_SECRET_SALT_FOR_DETERMINISTIC_HASHING_12345"
secret_salt_env = os.environ.get("OCPP_ANONYMIZER_SECRET_SALT", DEFAULT_SALT)
SECRET_SALT = secret_salt_env.encode("utf-8")

if secret_salt_env == DEFAULT_SALT:
    warnings.warn(
        "Using default SECRET_SALT. For production use, set the OCPP_ANONYMIZER_SECRET_SALT environment variable.",
        UserWarning,
    )


def hash_value(value: str) -> str | None:
    """Generates a consistent SHA256 hash token for the input string."""
    if value is None:
        return None
    # Concatenate the string value with the secret salt before hashing
    data = str(value).encode("utf-8") + SECRET_SALT
    # Use the first 16 characters for a reasonably short, unique token
    return hashlib.sha256(data).hexdigest()[:16]


def anonymize_url(url: str) -> str:
    """Removes credentials (user:password) from sensitive URLs like FTP/S."""
    if not isinstance(url, str):
        return "[INVALID_URL_MASKED]"

    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return "[INVALID_URL_MASKED]"

        # Check for schemes that typically embed credentials
        if parsed.scheme in ["ftp", "ftps", "http", "https"]:
            # Rebuild netloc without user:password, keep host:port
            netloc_parts = parsed.netloc.split("@")
            if len(netloc_parts) > 1:
                # Credentials were present, keep only host:port
                new_netloc = netloc_parts[-1]
            else:
                new_netloc = parsed.netloc

            # Reconstruct the URL without credentials
            return urlunparse(parsed._replace(netloc=new_netloc))
    except ValueError:
        return "[INVALID_URL_MASKED]"

    return url  # Return original if no credentials were found or protocol unrecognized
