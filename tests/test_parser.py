# tests/test_parser.py

import os
import unittest
import json
from ocpp_anonymizer.parser import process_log_line
from ocpp_anonymizer.hasher import hash_value

class TestParser(unittest.TestCase):

    def test_process_log_line_call(self):
        """Test a standard CALL message."""
        log_line = 'CP123 : receive [2, "12345", "StartTransaction", {"idTag": "USER1", "meterStart": 100}]'
        cp_id_token = hash_value("CP123")
        id_tag_token = hash_value("USER1")
        
        expected_json = f'[2, "12345", "StartTransaction", {{"idTag": "{id_tag_token}", "meterStart": 100}}]'
        expected_output = f'{cp_id_token} : receive message [{expected_json[1:-1]}]'

        # Manually constructing the expected output due to dictionary ordering
        processed_line = process_log_line(log_line)
        
        # Parse the JSON parts to compare them irrespective of key order
        processed_json_str = processed_line[processed_line.find('[') + 1 : processed_line.rfind(']')]
        expected_json_str = expected_output[expected_output.find('[') + 1 : expected_output.rfind(']')]
        
        processed_data = json.loads(f"[{processed_json_str}]")
        expected_data = json.loads(f"[{expected_json_str}]")

        # Compare the structured data
        self.assertEqual(processed_data[0], expected_data[0])
        self.assertEqual(processed_data[1], expected_data[1])
        self.assertEqual(processed_data[2], expected_data[2])
        self.assertDictEqual(processed_data[3], expected_data[3])

    def test_process_log_line_call_result(self):
        """Test a standard CALLRESULT message."""
        log_line = 'CP456 : send [3, "67890", {"status": "Accepted", "transactionId": 987}]'
        cp_id_token = hash_value("CP456")
        transaction_id_token = hash_value("987")
        
        expected_json = f'[3, "67890", {{"status": "Accepted", "transactionId": "{transaction_id_token}"}}]'
        expected_output = f'{cp_id_token} : send message [{expected_json[1:-1]}]'
        
        processed_line = process_log_line(log_line)
        
        processed_json_str = processed_line[processed_line.find('[') + 1 : processed_line.rfind(']')]
        expected_json_str = expected_output[expected_output.find('[') + 1 : expected_output.rfind(']')]
        
        processed_data = json.loads(f"[{processed_json_str}]")
        expected_data = json.loads(f"[{expected_json_str}]")

        self.assertEqual(processed_data[0], expected_data[0])
        self.assertEqual(processed_data[1], expected_data[1])
        self.assertDictEqual(processed_data[2], expected_data[2])

    def test_process_log_line_no_match(self):
        """Test a line that doesn't match the regex."""
        log_line = "This is not an OCPP log line."
        self.assertEqual(process_log_line(log_line), log_line)

    def test_process_log_line_invalid_json(self):
        """Test a line with invalid JSON."""
        log_line = 'CP789 : receive [2, "abc", "Action", {key: "value"}]' # Invalid JSON
        cp_id_token = hash_value("CP789")
        expected_output = f'{cp_id_token} : receive message [2, "abc", "Action", {{key: "value"}}]'
        self.assertEqual(process_log_line(log_line), expected_output)

if __name__ == '__main__':
    unittest.main()
