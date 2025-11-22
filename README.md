# OCPP-Anonymizer: Deterministic PII Redaction

[![PyPI version](https://badge.fury.io/py/ocpp-anonymizer.svg)](https://badge.fury.io/py/ocpp-anonymizer)

A Python library for anonymizing OCPP log files while preserving the ability to trace sessions and identify unique devices.

## The Problem

OCPP (Open Charge Point Protocol) logs are essential for debugging EV charging issues, but they often contain Personally Identifiable Information (PII) and other sensitive data. This includes:

*   **`idTag`**: A user's unique identifier (e.g., RFID card number).
*   **Hardware Identifiers**: `chargeBoxSerialNumber`, `iccid`, `imsi`, etc.
*   **Transaction Data**: `transactionId` which links charging sessions.

Exposing this data can lead to privacy violations and security risks, making it difficult to share logs with developers or third parties.

## The Solution

This library redacts sensitive information by replacing it with a **deterministic SHA256 hash**. This means:

*   **Anonymity**: The original value cannot be reverse-engineered.
*   **Traceability**: The same input value (e.g., the same `idTag`) will always produce the same hash token. This allows you to track a user's activity across multiple log lines without knowing their actual identity.

The library also handles special cases like masking credentials in URLs and redacting `AuthorizationKey` values.

## Installation

```bash
pip install ocpp-anonymizer
```

## Usage

You can use the library in two primary ways:

### 1. Processing a Raw Log Line

If you have raw log files in the format `CP_ID : direction [JSON_PAYLOAD]`, you can process them line by line.

```python
from ocpp_anonymizer import process_log_line

raw_log = 'CP123 : receive [2, "12345", "StartTransaction", {"idTag": "USER1", "meterStart": 100}]'

anonymized_log = process_log_line(raw_log)

# The output will have the CP_ID and idTag hashed
print(anonymized_log)
# e.g., 'a1b2c3d4e5f6a7b8 : receive message [2, "12345", "StartTransaction", {"idTag": "f242c797e74b89bb", "meterStart": 100}]'
```

### 2. Anonymizing a Structured JSON Payload

If you have already parsed the JSON part of an OCPP message, you can anonymize the payload directly.

```python
from ocpp_anonymizer import anonymize_payload

action = "StartTransaction"
payload = {"idTag": "USER1", "meterStart": 100}

anonymized_payload = anonymize_payload(action, payload)

print(anonymized_payload)
# {'idTag': 'f242c797e74b89bb', 'meterStart': 100}
```

## Configuration

### **IMPORTANT: Change the Secret Salt**

The library uses a default `SECRET_SALT` for hashing. For production use, you **must** replace this with your own unique, randomly generated secret. This ensures that the generated hashes are unique to your environment.

You can change the salt by modifying the `SECRET_SALT` variable in `ocpp_anonymizer/hasher.py`.

```python
# src/ocpp_anonymizer/hasher.py
SECRET_SALT = b"YOUR_SUPER_SECRET_SALT_FOR_DETERMINISTIC_HASHING_12345"
```

## Contributing

Contributions are welcome! If you find a sensitive field that is not yet mapped in `ocpp_anonymizer/mapping.py`, please open an issue or submit a pull request.
