use std::process::Command;

fn run(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .args(args)
        .output()
        .expect("bootroot binary runs in tests");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

#[test]
fn test_help_lists_subcommands() {
    let (stdout, _stderr, code) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("infra"));
    assert!(stdout.contains("init"));
    assert!(stdout.contains("status"));
    assert!(stdout.contains("app"));
    assert!(stdout.contains("verify"));
}

#[test]
fn test_status_command_message() {
    let (stdout, _stderr, code) = run(&["status"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("bootroot status: not yet implemented"));
}
