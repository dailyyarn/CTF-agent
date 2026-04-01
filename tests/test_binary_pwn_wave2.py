import unittest

from ctf_agent.solvers.binary import BinarySolver


class BinaryPwnWave2Tests(unittest.TestCase):
    def test_recommended_remote_templates_preserve_probe_order(self):
        solver = BinarySolver(file_tool=None, shell_tool=None, verifier=object(), toolkit_tool=None, remote_tool=None, mcp_registry=None)
        templates = solver._recommended_remote_templates(
            "pwn",
            {
                "pwn_capabilities": {
                    "recommended_templates": [
                        "pwn-env-doctor",
                        "binary-checksec",
                        "pwntools-probe",
                        "input-bruteforce-lite",
                        "pwn-libc-setup",
                    ]
                }
            },
        )
        self.assertEqual(
            ["pwn-env-doctor", "binary-checksec", "pwntools-probe", "input-bruteforce-lite", "pwn-libc-setup"],
            templates,
        )

    def test_qemu_lane_is_used_for_non_x86_arch(self):
        solver = BinarySolver(file_tool=None, shell_tool=None, verifier=object(), toolkit_tool=None, remote_tool=None, mcp_registry=None)
        self.assertTrue(solver._should_use_qemu_lane({"arch": "aarch64"}, {}))
        self.assertFalse(solver._should_use_qemu_lane({"arch": "x86_64"}, {}))


if __name__ == "__main__":
    unittest.main()
