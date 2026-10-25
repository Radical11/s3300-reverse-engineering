"""Synthetic USB descriptor parser checks; never open a device."""
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from read_usb_descriptors import parse_configuration

CONFIG = bytes.fromhex("09022700010100c0fa090400000306010100070501020002000705810200020007058203080010")


class DescriptorTests(unittest.TestCase):
    def test_still_image_configuration_maps_directions_and_transfers(self):
        result = parse_configuration(CONFIG)
        self.assertEqual(result["total_bytes"], 39)
        self.assertEqual(result["configuration_value"], 1)
        self.assertEqual(len(result["interfaces"]), 1)
        interface = result["interfaces"][0]
        self.assertEqual((interface["number"], interface["alternate"], interface["class"],
                          interface["subclass"], interface["protocol"]), (0, 0, 6, 1, 1))
        self.assertEqual([(e["address"], e["direction"], e["transfer_type"], e["max_packet_bytes"])
                          for e in interface["endpoints"]],
                         [(1, "out", "bulk", 512), (129, "in", "bulk", 512),
                          (130, "in", "interrupt", 8)])

    def test_truncation_and_tail_are_rejected(self):
        for value in (b"", CONFIG[:8], CONFIG[:-1], CONFIG + b"\0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_configuration(value)

    def test_zero_or_overrunning_descriptor_length_is_rejected(self):
        for length in (0, 1, 255):
            value = bytearray(CONFIG); value[18] = length
            with self.subTest(length=length), self.assertRaises(ValueError):
                parse_configuration(bytes(value))

    def test_endpoint_requires_interface(self):
        value = bytearray(CONFIG[:9] + CONFIG[18:])
        struct.pack_into("<H", value, 2, len(value))
        with self.assertRaisesRegex(ValueError, "without"):
            parse_configuration(bytes(value))

    def test_count_mismatch_and_duplicate_endpoint_are_rejected(self):
        for index, replacement in ((4, 2), (13, 4), (27, 1)):
            value = bytearray(CONFIG); value[index] = replacement
            with self.subTest(index=index), self.assertRaises(ValueError):
                parse_configuration(bytes(value))

    def test_distinct_alternates_can_share_interface_number(self):
        extra = bytes.fromhex("090400010006010100")
        value = bytearray(CONFIG + extra)
        struct.pack_into("<H", value, 2, len(value))
        result = parse_configuration(bytes(value))
        self.assertEqual(len(result["interfaces"]), 2)
        self.assertEqual(result["declared_interfaces"], 1)
        value[-6] = 0
        with self.assertRaisesRegex(ValueError, "identities"):
            parse_configuration(bytes(value))


class CommandBoundaryTests(unittest.TestCase):
    def test_camera_usb_command_rejects_source_tree_without_contact(self):
        import workspace_cli
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(workspace_cli, "ROOT", root), patch.object(workspace_cli, "run_tool") as run:
                result = workspace_cli.main(["camera-usb", str(root / "public.json")])
                self.assertEqual(result, 1)
                run.assert_not_called()

    def test_camera_usb_command_refuses_existing_report(self):
        import workspace_cli
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / "derived/keep.json"
            output.parent.mkdir(); output.write_text("keep")
            with patch.object(workspace_cli, "ROOT", root), patch.object(workspace_cli, "run_tool") as run:
                result = workspace_cli.main(["camera-usb", str(output)])
                self.assertEqual(result, 1)
                run.assert_not_called()
            self.assertEqual(output.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
