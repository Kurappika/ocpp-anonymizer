# src/ocpp_anonymizer/anonymizer.py

from .hasher import hash_value, anonymize_url
from .mapping import SENSITIVE_FIELDS_MAP, SPECIAL_HANDLING_FIELDS


def _safe_get_set(payload: dict, path: str, value=None, hash_func=None) -> bool:
    """Safely navigates nested dictionary structure for getting or setting values."""
    keys = path.split(".")
    current = payload

    for i, key in enumerate(keys):
        if isinstance(current, dict) and key in current:
            if i == len(keys) - 1:
                if value is not None:
                    # Set operation
                    current[key] = value
                elif hash_func:
                    # Hash operation
                    original_value = current[key]
                    if original_value is not None:
                        current[key] = hash_func(original_value)
                return True  # Success
            current = current[key]
        else:
            return False  # Key not found
    return False


def anonymize_payload(action: str, payload: dict) -> dict:
    """
    Anonymizes sensitive fields within a single OCPP message payload (dict).

    Args:
        action (str): The OCPP command (e.g., 'StartTransaction').
        payload (dict): The message arguments payload.
    """

    # 1. Handle Standard Sensitive Fields (idTags, transactionIds, hardware data)
    fields_to_hash = SENSITIVE_FIELDS_MAP.get(action, [])

    # Add nested fields common in 'conf' messages
    if action.endswith("conf") or action == "CONF_MESSAGES_NESTED_CHECK":
        # Add general sensitive fields for responses, ensuring 'transactionId' is covered.
        fields_to_hash.extend(SENSITIVE_FIELDS_MAP.get("CONF_MESSAGES_NESTED", []))

    for field_path in fields_to_hash:
        # Handle nested lists/dictionaries (e.g., localAuthorizationList)
        if isinstance(field_path, tuple):
            list_key, item_key = field_path
            if list_key in payload and isinstance(payload[list_key], list):
                for item in payload[list_key]:
                    if item_key in item:
                        # Direct hash for the list item (e.g., idTag in localAuthorizationList)
                        item[item_key] = hash_value(item[item_key])
                    # Note: You may need a deeper check for idTagInfo.parentIdTag here
                    # if it's found nested in lists other than the .conf response.

        # Handle top-level and nested key paths (e.g., 'transactionId', 'idTagInfo.parentIdTag')
        elif field_path in payload or "." in field_path:
            _safe_get_set(payload, field_path, hash_func=hash_value)

    # 2. Handle fields requiring Special Processing (URLs, AuthorizationKey)

    # a) URLs (GetDiagnostics, UpdateFirmware, GetLog)
    special_fields = SPECIAL_HANDLING_FIELDS.get(action)

    if special_fields:
        if isinstance(special_fields, str) and special_fields in payload:
            # Direct field access (e.g., 'location' in UpdateFirmware.req)
            if isinstance(payload[special_fields], str):
                payload[special_fields] = anonymize_url(payload[special_fields])

        elif isinstance(special_fields, tuple):
            # Nested field access (e.g., ('log', 'remoteLocation') in GetLog.req)
            parent_key, url_key = special_fields
            if (
                parent_key in payload
                and url_key in payload[parent_key]
                and isinstance(payload[parent_key], dict)
            ):
                if isinstance(payload[parent_key][url_key], str):
                    payload[parent_key][url_key] = anonymize_url(
                        payload[parent_key][url_key]
                    )

    # b) AuthorizationKey in ChangeConfiguration.req
    if (
        action == "ChangeConfiguration"
        and "key" in payload
        and payload["key"] == "AuthorizationKey"
    ):
        payload["value"] = "[AUTHORIZATION_KEY_MASKED]"

    return payload
