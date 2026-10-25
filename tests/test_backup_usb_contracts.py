"""Offline setup classification/bounds tests; no device or transport is used."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from map_backup_usb_contracts import (setup_event_mask, setup_wait_mask,
    inspect_observed_setup, ptp_string_extent, build_report)


class BackupUsbContractTests(unittest.TestCase):
    def test_all_request_type_bits_preserve_type_classification(self):
        # Direction/recipient bits do not become an inferred opcode allowlist.
        for kind,expected in ((0,0x100),(1,0x400),(2,0x200),(3,0)):
            for low in range(32):
                for direction in (0,0x80):
                    self.assertEqual(setup_event_mask(direction|kind<<5|low,0,1),expected)

    def test_nonready_wakes_both_classes_without_accepting_a_command(self):
        for status in (0,2,3,6,255):
            self.assertEqual(setup_event_mask(0x40,0,status),0x600)
        self.assertEqual(setup_event_mask(0x40,2,0),0)
        self.assertEqual(setup_event_mask(0x40,2,1),0)

    def test_standard_handled_does_not_wake_debug(self):
        self.assertEqual(setup_event_mask(0x80,0,1,standard_handled=True),0)
        self.assertEqual(setup_wait_mask(6),0x600)
        self.assertEqual(setup_wait_mask(3),0x500)
        self.assertEqual(setup_wait_mask(7),0x700)
        self.assertEqual(setup_wait_mask(0),0)

    def test_reader_uses_recipient_parity_not_a_complete_recipient_check(self):
        for low in range(32):
            observed=bytes([0x40|low,0x00,0x03,0x20,0x00,0x00,0x08,0x00])
            result=inspect_observed_setup(observed)
            self.assertEqual(result['route'], 'mass-storage-class-handler' if low&1 else 'debug-dispatch-candidate')
            self.assertFalse(result['safe_host_request'])
            self.assertEqual(result['internal_index'],None if low&1 else 0x20)

    def test_request_and_index_are_observed_but_not_reader_allowlisted(self):
        result=inspect_observed_setup(bytes.fromhex('40a50320ffff0800'))
        self.assertEqual((result['request'],result['index']),(0xa5,0xffff))
        self.assertEqual((result['internal_index'],result['subcommand']),(0x20,3))
        self.assertFalse(result['safe_host_request'])

    def test_disconnect_precedes_forwarding_and_zero_length_ack(self):
        observed=bytes.fromhex('4000032000000000')
        self.assertTrue(inspect_observed_setup(observed)['zero_length_status_before_dispatch'])
        stopped=inspect_observed_setup(observed,disconnect_pending=True)
        self.assertEqual(stopped['route'],'stop')
        self.assertIsNone(stopped['internal_index'])
        self.assertFalse(stopped['zero_length_status_before_dispatch'])

    def test_16_bit_control_length_can_exceed_dispatch_allocation(self):
        exact=inspect_observed_setup(bytes.fromhex('4000032000000020'))
        overflow=inspect_observed_setup(bytes.fromhex('4000032000000120'))
        self.assertFalse(exact['host_to_device_control_length_exceeds_dispatch_buffer'])
        self.assertTrue(overflow['host_to_device_control_length_exceeds_dispatch_buffer'])
        self.assertFalse(inspect_observed_setup(bytes.fromhex('c00003200000ffff'))['host_to_device_control_length_exceeds_dispatch_buffer'])

    def test_ordinary_string_includes_terminator_and_boundary_failure_is_visible(self):
        self.assertEqual(ptp_string_extent(5),dict(wire_count=6,copied_low_bytes=6,zero_fill_bytes=12,
            full_input_and_terminator_represented=True))
        self.assertEqual(ptp_string_extent(254)['wire_count'],255)
        broken=ptp_string_extent(255)
        self.assertEqual((broken['wire_count'],broken['copied_low_bytes']),(0,255))
        self.assertFalse(broken['full_input_and_terminator_represented'])
        self.assertEqual(ptp_string_extent(256)['wire_count'],0)
        self.assertFalse(ptp_string_extent(256)['full_input_and_terminator_represented'])

    def test_invalid_observations_and_changed_source_rejected(self):
        for value in (-1,256,True,'6'):
            with self.assertRaises(ValueError): setup_wait_mask(value)
        for value in (b'',bytes(7),bytes(9),'12345678'):
            with self.assertRaises(ValueError): inspect_observed_setup(value)
        for value in (-1,True,1<<32):
            with self.assertRaises(ValueError): ptp_string_extent(value)
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/'changed.bin';source.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'source identity'):
                build_report(Path(folder),source,Path(folder))


if __name__=='__main__': unittest.main()
