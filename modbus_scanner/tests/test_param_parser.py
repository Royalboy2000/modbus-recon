# modbus_scanner/tests/test_param_parser.py
import unittest
from modbus_scanner.utils.param_parser import parse_unit_ids

class TestParamParser(unittest.TestCase):

    def test_parse_single_unit_id(self):
        self.assertEqual(parse_unit_ids("1"), [1])

    def test_parse_multiple_unit_ids_comma_separated(self):
        self.assertEqual(parse_unit_ids("1,2,3"), [1, 2, 3])

    def test_parse_unit_id_range(self):
        self.assertEqual(parse_unit_ids("5-8"), [5, 6, 7, 8])

    def test_parse_mixed_single_and_range(self):
        self.assertEqual(parse_unit_ids("1,5-7,10"), [1, 5, 6, 7, 10])

    def test_parse_invalid_range_start_greater_than_end(self):
        self.assertEqual(parse_unit_ids("10-8"), [])

    def test_parse_with_spaces(self):
        self.assertEqual(parse_unit_ids("1, 2, 3 ,5-6"), [1, 2, 3, 5, 6])

    def test_parse_typical_modbus_range(self):
        self.assertEqual(parse_unit_ids("240-247"), list(range(240, 248)))

    def test_parse_full_allowed_range(self):
        self.assertEqual(parse_unit_ids("0,255"), [0, 255])

    def test_parse_range_exceeding_max_val(self):
        # Default max_val is 255
        self.assertEqual(parse_unit_ids("250-260"), list(range(250, 256)))

    def test_parse_range_below_min_val(self):
        # Default min_val is 0. "-5-2" is an invalid format for start of range.
        self.assertEqual(parse_unit_ids("-5-2"), [])

    def test_parse_with_invalid_parts(self):
        # "abc" and "def-ghi" should be skipped
        self.assertEqual(parse_unit_ids("1,abc,5-8,def-ghi,10"), [1, 5, 6, 7, 8, 10])

    def test_parse_empty_string(self):
        self.assertEqual(parse_unit_ids(""), [])

    def test_parse_comma_only(self):
        self.assertEqual(parse_unit_ids(",,"), [])

    def test_parse_duplicates(self):
        self.assertEqual(parse_unit_ids("1,1,2,2,5-6,5-6"), [1, 2, 5, 6])

    def test_parse_with_custom_range_clamping(self):
        # Test with min_val=1, max_val=247
        custom_min = 1
        custom_max = 247
        result = parse_unit_ids("0,1,247,248,100-110,250-255", min_val=custom_min, max_val=custom_max)
        expected = sorted(list(set([1] + list(range(100, 111)) + [247])))
        self.assertEqual(result, expected)

    def test_parse_single_number_out_of_custom_range(self):
        self.assertEqual(parse_unit_ids("0", min_val=1, max_val=247), [])
        self.assertEqual(parse_unit_ids("248", min_val=1, max_val=247), [])
        self.assertEqual(parse_unit_ids("10", min_val=1, max_val=5), [])


if __name__ == '__main__':
    unittest.main()
