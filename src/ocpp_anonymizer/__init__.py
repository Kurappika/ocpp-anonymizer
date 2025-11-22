# src/ocpp_anonymizer/__init__.py

# Expose core functions for easy import:
from .hasher import hash_value
from .anonymizer import anonymize_payload
from .parser import process_log_line

# Define what happens when a user imports the package
__all__ = [
    'hash_value',
    'anonymize_payload',
    'process_log_line',
]

__version__ = '0.1.0' # Keep version here