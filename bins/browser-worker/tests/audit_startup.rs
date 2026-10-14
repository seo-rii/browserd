use std::error::Error;
use std::process::Command;

fn startup(directory: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_browser-worker"));
    command
        .env_clear()
        .env("BROWSERD_WORKER_ID", "audit-startup-test")
        .env("BROWSERD_WORKER_EPOCH_FILE", directory.join("worker.epoch"))
        .env(
            "BROWSERD_INTERNAL_ENDPOINT",
            format!("unix:{}", directory.join("worker.sock").display()),
        )
        .env("BROWSERD_INTERNAL_PEER", "test-gateway")
        .env("BROWSERD_ACTION_JOURNAL_DIR", directory.join("actions"))
        .env("BROWSERD_SANDBOX_SOCKET", directory.join("sandbox.sock"))
        .env("BROWSERD_SANDBOX_EXPECTED_SERVER_UID", "0")
        .env("BROWSERD_SANDBOXD_EPOCH", "1");
    command
}

#[test]
fn production_requires_audit_configuration_before_epoch_mutation() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir(directory.path().join("actions"))?;
    let output = startup(directory.path()).output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("BROWSERD_AUDIT_WAL_FILE is required"));
    assert!(!directory.path().join("worker.epoch").exists());
    assert!(!directory.path().join("worker.sock").exists());
    Ok(())
}

#[test]
fn production_rejects_relative_audit_path_before_epoch_mutation() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir(directory.path().join("actions"))?;
    let output = startup(directory.path())
        .env("BROWSERD_AUDIT_WAL_FILE", "audit.wal")
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("BROWSERD_AUDIT_WAL_FILE must be absolute"));
    assert!(!directory.path().join("worker.epoch").exists());
    Ok(())
}

#[test]
fn production_rejects_relative_secret_catalog_before_epoch_mutation() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    std::fs::create_dir(directory.path().join("actions"))?;
    let output = startup(directory.path())
        .env(
            "BROWSERD_AUDIT_WAL_FILE",
            directory.path().join("audit.wal"),
        )
        .env("BROWSERD_SECRET_CONFIG_FILE", "secrets.json")
        .output()?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)?.contains("BROWSERD_SECRET_CONFIG_FILE must be absolute")
    );
    assert!(!directory.path().join("worker.epoch").exists());
    assert!(!directory.path().join("worker.sock").exists());
    Ok(())
}

#[test]
fn production_rejects_relative_evaluate_policy_before_epoch_mutation() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    std::fs::create_dir(directory.path().join("actions"))?;
    let output = startup(directory.path())
        .env(
            "BROWSERD_AUDIT_WAL_FILE",
            directory.path().join("audit.wal"),
        )
        .env("BROWSERD_PRIVILEGED_EVALUATE_POLICY_FILE", "evaluate.json")
        .output()?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)?
            .contains("BROWSERD_PRIVILEGED_EVALUATE_POLICY_FILE must be absolute")
    );
    assert!(!directory.path().join("worker.epoch").exists());
    assert!(!directory.path().join("worker.sock").exists());
    Ok(())
}

#[test]
fn production_rejects_invalid_evaluate_policy_before_epoch_mutation() -> Result<(), Box<dyn Error>>
{
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    std::fs::create_dir(directory.path().join("actions"))?;
    let policy = directory.path().join("evaluate.json");
    std::fs::write(&policy, b"{\"schema_version\":2,\"grants\":[]}")?;
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600))?;
    let output = startup(directory.path())
        .env(
            "BROWSERD_AUDIT_WAL_FILE",
            directory.path().join("audit.wal"),
        )
        .env("BROWSERD_PRIVILEGED_EVALUATE_POLICY_FILE", &policy)
        .output()?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)?
            .contains("privileged evaluate policy could not be opened")
    );
    assert!(!directory.path().join("worker.epoch").exists());
    assert!(!directory.path().join("worker.sock").exists());
    Ok(())
}

#[test]
fn production_rejects_incomplete_or_relative_checkpoint_configuration_before_epoch_mutation()
-> Result<(), Box<dyn Error>> {
    for (root, key, expected) in [
        (
            Some("/tmp/checkpoints"),
            None,
            "checkpoint storage requires both root and key file",
        ),
        (
            None,
            Some("/tmp/key"),
            "checkpoint storage requires both root and key file",
        ),
        (
            Some("relative"),
            Some("/tmp/key"),
            "checkpoint storage paths must be absolute",
        ),
        (
            Some("/tmp/checkpoints"),
            Some("relative"),
            "checkpoint storage paths must be absolute",
        ),
    ] {
        let directory = tempfile::tempdir()?;
        std::fs::create_dir(directory.path().join("actions"))?;
        let mut command = startup(directory.path());
        command.env(
            "BROWSERD_AUDIT_WAL_FILE",
            directory.path().join("audit.wal"),
        );
        if let Some(root) = root {
            command.env("BROWSERD_CHECKPOINT_ROOT", root);
        }
        if let Some(key) = key {
            command.env("BROWSERD_CHECKPOINT_KEY_FILE", key);
        }
        let output = command.output()?;
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)?.contains(expected));
        assert!(!directory.path().join("worker.epoch").exists());
        assert!(!directory.path().join("worker.sock").exists());
    }
    Ok(())
}

#[test]
fn production_requires_control_journal_before_epoch_mutation() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    std::fs::create_dir(directory.path().join("actions"))?;
    let output = startup(directory.path())
        .env(
            "BROWSERD_AUDIT_WAL_FILE",
            directory.path().join("audit.wal"),
        )
        .output()?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)?
            .contains("BROWSERD_CONTROL_EVENT_JOURNAL_FILE is required")
    );
    assert!(!directory.path().join("worker.epoch").exists());
    Ok(())
}
