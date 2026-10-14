"""Host setup must remain confined to one delegated, unprivileged unit."""

import importlib.util
import pathlib
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch


SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "deploy/setup-validation-host.py"
SPEC = importlib.util.spec_from_file_location("setup_validation_host", SCRIPT)
host = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host)


class HostSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = pathlib.Path(self.temp.name)
        self.repo = self.home / "browserd"
        (self.repo / "deploy").mkdir(parents=True)
        (self.repo / "scripts").mkdir()
        (self.repo / "deploy/setup-validation-host.py").write_text("# fixture\n")
        (self.repo / "scripts/validation.py").write_text("# fixture\n")
        self.state = self.home / "state"
        self.user = types.SimpleNamespace(
            pw_name="seorii", pw_uid=1003, pw_gid=1003, pw_dir=str(self.home)
        )
        self.lookup = patch.object(host.pwd, "getpwnam", return_value=self.user)
        self.lookup.start()
        self.addCleanup(self.lookup.stop)
        self.addCleanup(self.temp.cleanup)

    def plan(self, **changes):
        values = {"user": "seorii", "repo": str(self.repo), "state_dir": str(self.state)}
        values.update(changes)
        return host.make_plan(**values)

    def test_render_is_stable_and_confined_to_a_dedicated_unit(self):
        plan = self.plan()
        self.assertEqual(plan, self.plan())
        self.assertRegex(plan["unit_name"], r"^browserd-validation-u1003-[0-9a-f]{12}\.service$")
        self.assertEqual(plan["unit_path"], "/etc/systemd/system/" + plan["unit_name"])
        self.assertNotIn("code-server", plan["unit_content"])
        self.assertIn("User=1003\nGroup=1003\n", plan["unit_content"])
        self.assertIn("Delegate=cpu memory pids\n", plan["unit_content"])
        self.assertIn("NoNewPrivileges=yes\n", plan["unit_content"])
        self.assertIn("KillMode=control-group\n", plan["unit_content"])
        self.assertNotIn("BROWSERD_TRUSTED_VALIDATION", plan["unit_content"])
        self.assertNotIn("BROWSERD_KERNEL_RUNNER", plan["unit_content"])
        self.assertNotIn("BROWSERD_SOAK_RUNNER", plan["unit_content"])
        self.assertEqual(plan["socket_path"], str(self.state / "control.sock"))

    def test_state_changes_give_a_separate_unit_identity(self):
        self.assertNotEqual(self.plan()["unit_name"], self.plan(state_dir=str(self.home / "other"))["unit_name"])

    def test_paths_are_quoted_without_expanding_systemd_specifiers_or_environment(self):
        special = self.home / 'browserd %n $HOME "quoted" \\path'
        self.repo.rename(special)
        plan = self.plan(repo=str(special))
        self.assertIn('%%n $$HOME \\"quoted\\" \\\\path', plan["unit_content"])
        self.assertNotIn("WorkingDirectory=", plan["unit_content"])
        self.assertIn("--apply", plan["host_command"])

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd parser is unavailable")
    def test_rendered_unit_is_accepted_by_the_actual_systemd_parser(self):
        plan = self.plan()
        unit = self.home / plan["unit_name"]
        unit.write_text(plan["unit_content"])
        result = subprocess.run(["systemd-analyze", "verify", str(unit)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_root_user_is_rejected(self):
        self.user.pw_uid = 0
        with self.assertRaisesRegex(host.SetupError, "non-root"):
            self.plan()

    def test_unknown_user_is_rejected(self):
        with patch.object(host.pwd, "getpwnam", side_effect=KeyError):
            with self.assertRaisesRegex(host.SetupError, "unknown user"):
                self.plan()

    def test_relative_and_ambiguous_paths_are_rejected(self):
        for key in ("repo", "state_dir"):
            for path in ("relative/path", str(self.home) + "/../escape", str(self.home) + "/bad\npath"):
                with self.subTest(key=key, path=path):
                    with self.assertRaises(host.SetupError):
                        self.plan(**{key: path})

    def test_state_must_be_below_the_unprivileged_users_home(self):
        with self.assertRaisesRegex(host.SetupError, "home"):
            self.plan(state_dir="/etc/browserd-validation")

    def test_symlink_path_component_is_rejected(self):
        (self.home / "alias").symlink_to(self.repo, target_is_directory=True)
        with self.assertRaisesRegex(host.SetupError, "symlink"):
            self.plan(repo=str(self.home / "alias"))

    def test_repository_must_have_its_fixed_validation_entrypoint(self):
        (self.repo / "scripts/validation.py").unlink()
        with self.assertRaisesRegex(host.SetupError, "validation.py"):
            self.plan()

    def test_unit_installation_is_idempotent(self):
        path = self.home / "unit.service"
        self.assertTrue(host.install_unit(path, "exact unit\n"))
        self.assertFalse(host.install_unit(path, "exact unit\n"))
        self.assertEqual(path.read_text(), "exact unit\n")
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_existing_different_unit_is_never_overwritten(self):
        path = self.home / "unit.service"
        path.write_text("somebody else's unit\n")
        with self.assertRaisesRegex(host.SetupError, "differs"):
            host.install_unit(path, "our unit\n")
        self.assertEqual(path.read_text(), "somebody else's unit\n")

    def test_unit_symlinks_are_never_followed(self):
        target = self.home / "target.service"
        target.write_text("untouched\n")
        link = self.home / "unit.service"
        link.symlink_to(target)
        with self.assertRaisesRegex(host.SetupError, "symlink"):
            host.install_unit(link, "new\n")
        self.assertEqual(target.read_text(), "untouched\n")

    def test_existing_nonregular_unit_fails_without_opening_a_fifo(self):
        path = self.home / "unit.service"
        host.os.mkfifo(path)
        with self.assertRaisesRegex(host.SetupError, "regular"):
            host.install_unit(path, "new\n")

    def test_state_socket_path_must_fit_unix_domain_socket_limit(self):
        with self.assertRaisesRegex(host.SetupError, "socket"):
            self.plan(state_dir=str(self.home / ("x" * 100)))

    def test_nonroot_apply_fails_before_any_file_or_service_operation(self):
        with patch.object(host.os, "geteuid", return_value=1003), patch.object(host, "install_unit") as install:
            with self.assertRaisesRegex(host.SetupError, "root"):
                host.apply(self.plan())
            install.assert_not_called()

    def test_request_only_allows_fixed_validation_actions(self):
        self.assertEqual(host.validate_request({"action": "diagnose", "environment": {}}), ("diagnose", {}))
        self.assertEqual(host.validate_request({"action": "kernel", "environment": {}}), ("kernel", {}))
        for request in ({"action": "shell"}, {"action": "kernel", "argv": ["/bin/sh"]}, {"action": "kernel", "environment": {"LD_PRELOAD": "/tmp/inject"}}):
            with self.subTest(request=request):
                with self.assertRaises(host.SetupError):
                    host.validate_request(request)

    def test_explicit_environment_is_preserved_without_adding_qualification(self):
        environment = {"BROWSERD_CHROMIUM_ARTIFACT_ROOT": str(self.home / "artifact")}
        self.assertEqual(host.validate_request({"action": "kernel", "environment": environment})[1], environment)
        self.assertNotIn("BROWSERD_TRUSTED_VALIDATION", environment)
        self.assertNotIn("BROWSERD_KERNEL_RUNNER", environment)
        self.assertNotIn("BROWSERD_SOAK_RUNNER", environment)

    def test_optional_approval_path_and_digest_are_forwarded_only_as_an_explicit_pair(self):
        environment = {"BROWSERD_KERNEL_PROBE_CONFIG": "/etc/browserd/kernel-probe-approval.json",
                       "BROWSERD_KERNEL_PROBE_CONFIG_SHA256": "a" * 64}
        self.assertEqual(host.validate_request({"action": "kernel", "environment": environment})[1], environment)
        for invalid in ({"BROWSERD_KERNEL_PROBE_CONFIG": environment["BROWSERD_KERNEL_PROBE_CONFIG"]},
                        {"BROWSERD_KERNEL_PROBE_CONFIG_SHA256": "a" * 64},
                        dict(environment, BROWSERD_KERNEL_PROBE_CONFIG="relative"),
                        dict(environment, BROWSERD_KERNEL_PROBE_CONFIG_SHA256="0" * 64),
                        dict(environment, BROWSERD_KERNEL_PROBE_CONFIG_SHA256="not a digest")):
            with self.subTest(invalid=invalid), self.assertRaises(host.SetupError):
                host.validate_request({"action": "kernel", "environment": invalid})
        plan = self.plan()
        self.assertNotIn("BROWSERD_KERNEL_PROBE_CONFIG", plan["unit_content"])

    def test_nul_and_oversized_environment_are_rejected(self):
        for value in ("a\x00b", "x" * 16385):
            with self.assertRaises(host.SetupError):
                host.validate_request({"action": "kernel", "environment": {"BROWSERD_CHROMIUM_ARTIFACT_ROOT": value}})

    def test_kernel_command_is_fixed_to_the_repository_validation_script(self):
        self.assertEqual(host.validation_command(self.repo, "kernel"), ["/usr/bin/python3", str(self.repo / "scripts/validation.py"), "kernel"])
        with self.assertRaises(host.SetupError):
            host.validation_command(self.repo, "fast")

    def test_cgroup_location_is_only_a_real_cgroupfs_relative_path(self):
        self.assertEqual(host.cgroup_path("0::/system.slice/browserd-validation.service\n"), pathlib.Path("/sys/fs/cgroup/system.slice/browserd-validation.service"))
        for value in ("0::/../../tmp\n", "0::relative\n", "1:cpu:/unit\n", "0::/\n", "0::/unit\n0::/other\n"):
            with self.subTest(value=value):
                with self.assertRaises(host.SetupError):
                    host.cgroup_path(value)


if __name__ == "__main__":
    unittest.main()
