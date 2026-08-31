#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    fn project_path(relative: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
    }

    fn assert_succeeds(command: &mut Command, description: &str) {
        let output = command
            .output()
            .expect("the focused assertion command runs");
        assert!(
            output.status.success(),
            "{description} failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn registrar_redteam_boundary_assertions_are_conclusive_without_docker() {
        assert_succeeds(
            Command::new("bash").arg(project_path(
                "tests/e2e/registrar/registrar_redteam_assertions_test.sh",
            )),
            "bundle credential scan assertions",
        );
        assert_succeeds(
            Command::new("python3")
                .arg("-m")
                .arg("unittest")
                .arg(project_path("tests/e2e/registrar/test_redteam_client.py")),
            "unknown-operation client assertions",
        );
    }
}
