# src/ocpp_anonymizer/mapping.py

# Fields that typically contain PII or unique hardware identifiers, mapped 
# to the message action (OCPP method name).
SENSITIVE_FIELDS_MAP = {
    # User Identification Fields
    'Authorize': ['idTag'],
    'StartTransaction': ['idTag', 'reservationId'], 
    'StopTransaction': ['idTag', 'transactionId'],
    'RemoteStartTransaction': ['idTag'],
    'ReserveNow': ['idTag'],
    'SendLocalList': [('localAuthorizationList', 'idTag')], # Nested field

    # System/Hardware Identification Fields
    'BootNotification': [
        'chargePointVendor', 'chargePointModel', 'chargeBoxSerialNumber', 
        'chargePointSerialNumber', 'firmwareVersion', 'iccid', 'imsi', 
        'meterSerialNumber', 'meterType'
    ],

    # Transaction Linker
    'MeterValues': ['transactionId'],
    
    # Nested 'idTagInfo' fields (often in .conf messages)
    'CONF_MESSAGES_NESTED': ['idTagInfo.parentIdTag', 'transactionId'] 
}

# Configuration Keys and URL fields requiring special handling
SPECIAL_HANDLING_FIELDS = {
    'ChangeConfiguration': 'value', # Check if 'key' is AuthorizationKey
    'UpdateFirmware': 'location', 
    'GetDiagnostics': 'location',
    'GetLog': ('log', 'remoteLocation')
}
