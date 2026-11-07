use super::*;

#[test]
fn production_spawn_failure_retains_fixed_context_errno_and_no_child_ownership() {
    run_process_helper("spawn_diagnostics::std_process_spawn_failure_context_helper");
}

#[test]
#[ignore = "owns the configured launch descriptors only in an isolated subprocess"]
fn std_process_spawn_failure_context_helper() {
    if std::env::var_os("BROWSERD_PROCESS_HELPER").is_none() {
        return;
    }
    let _descriptors = install_required_launch_descriptors();
    // The executable is present and pinned, but its nonexistent interpreter makes the actual
    // Command::spawn fail with ENOENT after the prepared-launch descriptor setup.
    let (_executable_directory, bwrap) = executable_script(
        "#!/definitely/missing/browserd-spawn-test-interpreter\nprivate child body must not execute\n",
    );
    let (_cgroup_directory, request) = process_request_for(&bwrap);
    let process = StdLinuxProcessBackend::default();
    let token = LeaseId::new().to_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("isolated process runtime");
    let children = || {
        let mut retained = Vec::new();
        for task in std::fs::read_dir("/proc/self/task").expect("helper threads") {
            let task = task.expect("helper thread entry");
            let path = task.path().join("children");
            if let Ok(contents) = std::fs::read_to_string(path) {
                retained.extend(contents.split_whitespace().map(str::to_owned));
            }
        }
        retained.sort();
        retained
    };
    let before = children();
    runtime.block_on(async {
        for _ in 0..2 {
            let failure = process
                .spawn_prepared(&token, &request)
                .await
                .expect_err("the real missing interpreter must fail before child publication");
            let errno = std::io::Error::from_raw_os_error(nix::libc::ENOENT);
            assert_eq!(
                failure,
                SandboxError::Backend(format!("prepared process spawn: {errno}"))
            );
            assert_eq!(
                failure.to_string(),
                format!("sandbox backend failed: prepared process spawn: {errno}")
            );
            assert_eq!(
                process
                    .claim_cdp_pipes(&token, ChildIdentity::new(std::process::id(), 1))
                    .await
                    .expect_err("failed spawn must not retain registry-owned CDP capabilities"),
                SandboxError::Backend("prepared child ownership missing".into())
            );
            process
                .abort_spawned(&token, None)
                .await
                .expect("failed spawn has no cleanup owner to leak");
        }
    });
    assert_eq!(
        children(),
        before,
        "failed exec must reap its bootstrap child"
    );
}
