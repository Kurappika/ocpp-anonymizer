# tests/test_anonymizer.py

import unittest
from ocpp_anonymizer.anonymizer import anonymize_payload
from ocpp_anonymizer.hasher import hash_value

class TestAnonymizer(unittest.TestCase):

    def test_anonymize_authorize(self):
        payload = {"idTag": "USER123"}
        anonymized = anonymize_payload("Authorize", payload)
        self.assertEqual(anonymized["idTag"], hash_value("USER123"))

    def test_anonymize_start_transaction(self):
        payload = {"idTag": "USER123", "reservationId": 456}
        anonymized = anonymize_payload("StartTransaction", payload)
        self.assertEqual(anonymized["idTag"], hash_value("USER123"))
        self.assertEqual(anonymized["reservationId"], hash_value("456"))

    def test_anonymize_stop_transaction(self):
        payload = {"idTag": "USER123", "transactionId": 789}
        anonymized = anonymize_payload("StopTransaction", payload)
        self.assertEqual(anonymized["idTag"], hash_value("USER123"))
        self.assertEqual(anonymized["transactionId"], hash_value("789"))

    def test_anonymize_boot_notification(self):
        payload = {
            "chargePointVendor": "VendorX",
            "chargePointModel": "ModelY",
            "chargeBoxSerialNumber": "SN123",
            "chargePointSerialNumber": "CPSN456",
            "firmwareVersion": "1.0",
            "iccid": "ICCID789",
            "imsi": "IMSI101",
            "meterSerialNumber": "MSN112",
            "meterType": "TypeZ"
        }
        anonymized = anonymize_payload("BootNotification", payload)
        self.assertEqual(anonymized["chargePointVendor"], hash_value("VendorX"))
        self.assertEqual(anonymized["chargePointModel"], hash_value("ModelY"))
        self.assertEqual(anonymized["chargeBoxSerialNumber"], hash_value("SN123"))
        self.assertEqual(anonymized["chargePointSerialNumber"], hash_value("CPSN456"))
        self.assertEqual(anonymized["firmwareVersion"], hash_value("1.0"))
        self.assertEqual(anonymized["iccid"], hash_value("ICCID789"))
        self.assertEqual(anonymized["imsi"], hash_value("IMSI101"))
        self.assertEqual(anonymized["meterSerialNumber"], hash_value("MSN112"))
        self.assertEqual(anonymized["meterType"], hash_value("TypeZ"))

    def test_anonymize_change_configuration(self):
        payload = {"key": "AuthorizationKey", "value": "KEY123"}
        anonymized = anonymize_payload("ChangeConfiguration", payload)
        self.assertEqual(anonymized["value"], "[AUTHORIZATION_KEY_MASKED]")

    def test_anonymize_update_firmware(self):
        payload = {"location": "ftp://user:pass@host/firmware.bin"}
        anonymized = anonymize_payload("UpdateFirmware", payload)
        self.assertEqual(anonymized["location"], "ftp://host/firmware.bin")

if __name__ == '__main__':
    unittest.main()
