"""Pure source-derived USB encoding/registration comparison checks."""
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tools/vendor')]
from map_usb_mode_contracts import endpoint_address,mode_contract,parse_usb_resource_rows


class UsbModeContractsTests(unittest.TestCase):
    def test_endpoint_direction_and_number(self):
        self.assertEqual([endpoint_address(x)for x in range(6)],[0,0x80,1,0x81,2,0x82])

    def test_whole_byte_encoding_is_bijective(self):
        self.assertEqual(len({endpoint_address(x)for x in range(256)}),256)

    def test_invalid_encoding_input_rejected(self):
        for x in (-1,256,None,'2'):
            with self.assertRaises(ValueError):endpoint_address(x)

    def test_two_ptp_modes_share_descriptor_comparison(self):
        a=mode_contract(4);b=mode_contract(7)
        self.assertEqual(a['endpoint_addresses'],[1,0x81,0x82])
        self.assertEqual(a['handle_slots'],[4,7])
        self.assertEqual({k:v for k,v in a.items()if k!='mode'},
            {k:v for k,v in b.items()if k!='mode'})

    def test_debug_mode_aliases_are_distinct_from_ptp(self):
        self.assertEqual(mode_contract(6)['handle_slots'],[6,5,0])
        self.assertEqual(mode_contract(6)['interface_classes'],[0,8])
        self.assertNotEqual(mode_contract(6)['interface_classes'],mode_contract(7)['interface_classes'])

    def test_unmapped_mode_not_inferred(self):
        for x in (0,5,8,255):
            with self.assertRaises(ValueError):mode_contract(x)

    def test_consumed_resource_fields_and_six_byte_mode_rows(self):
        rows=parse_usb_resource_rows(bytes.fromhex('b004c0fa0100'),bytes.fromhex(
            'bbbb020003001111000000002222000000003333000000002a03030004000803020005001620020004002a0303000400'))
        self.assertEqual(rows['device']['vendor_id_default'],0x04b0)
        self.assertEqual(rows['device']['config_attributes_default'],0xc0)
        self.assertEqual(rows['device']['power_byte_default'],250)
        self.assertEqual(rows['device']['manufacturer_string_selector'],1)
        for i in (4,7):
            self.assertEqual(rows['mode_rows'][i]['product_id_default'],0x032a)
            self.assertEqual(rows['mode_rows'][i]['product_string_selector'],3)
            self.assertEqual(rows['mode_rows'][i]['serial_string_selector'],4)
        self.assertEqual(rows['mode_rows'][6]['product_id_default'],0x2016)

    def test_resource_record_sizes_rejected(self):
        for device,modes in ((bytes(5),bytes(48)),(bytes(7),bytes(48)),
            (bytes(6),bytes(47)),(bytes(6),bytes(49))):
            with self.assertRaises(ValueError):parse_usb_resource_rows(device,modes)


if __name__=='__main__':unittest.main()
