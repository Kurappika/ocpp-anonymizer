# src/ocpp_anonymizer/parser.py

import json
import re

from .hasher import hash_value
from .anonymizer import anonymize_payload

# Regex to capture CP ID, direction, and the JSON array content.
# Handles optional 'message' keyword and whitespace.
LOG_LINE_REGEX = re.compile(r'^(.*?)\s*:\s*(receive|send)\s+(?:message\s+)?\[(.*?)]\s*$', re.IGNORECASE)

def process_log_line(log_line: str) -> str:
    """
    Parses a single raw log line, anonymizes sensitive parts, and returns the modified line.

    The expected log format is: 'CPID : direction [JSON_ARRAY]'
    """
    
    match = LOG_LINE_REGEX.match(log_line.strip())

    if not match:
        # If the log line doesn't match the expected OCPP structure, return it unmodified
        return log_line.strip()

    cp_id_original, direction, json_content = match.groups()
    
    # 1. Tokenize the Charge Point Identifier (CP ID)
    cp_id_token = hash_value(cp_id_original)

    # 2. Parse the OCPP JSON message array
    try:
        # Re-add brackets since regex captured internal content
        ocpp_message = json.loads(f'[{json_content}]')
    except json.JSONDecodeError:
        # If JSON decoding fails, return the original line with tokenized CP ID
        return f'{cp_id_token} : {direction} message [{json_content}]'

    # OCPP structure: [MessageTypeId, UniqueId, Action/Payload, Payload]
    if len(ocpp_message) < 3:
        return log_line.strip() 

    message_type_id = ocpp_message[0]
    
    if message_type_id == 2:  # CALL request/indication
        # [2, "UniqueId", "Action", {Payload}]
        if len(ocpp_message) == 4:
            action = ocpp_message[2]
            payload = ocpp_message[3]
            
            # Anonymize the payload in place
            anonymized_payload = anonymize_payload(action, payload)
            
            # Update the original list with the modified payload
            ocpp_message[3] = anonymized_payload
    
    elif message_type_id == 3: # CALLRESULT response
        # [3, "UniqueId", {Payload}]
        if len(ocpp_message) == 3:
            payload = ocpp_message[2]
            
            # Use a placeholder action to trigger general CONF field lookup
            anonymized_payload = anonymize_payload('CONF_MESSAGES_NESTED_CHECK', payload) 
            
            # Update the original list with the modified payload
            ocpp_message[2] = anonymized_payload
            
    # 3. Reconstruct the log line
    anonymized_json_content = json.dumps(ocpp_message)[1:-1] # Dump and strip surrounding brackets
    
    # Format: CPID_TOKEN : direction message [ANONYMIZED_JSON]
    return f'{cp_id_token} : {direction} message [{anonymized_json_content}]'
