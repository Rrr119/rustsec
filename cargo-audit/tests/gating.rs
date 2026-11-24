//! Offline tests for severity-based audit gating and ignore persistence.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const ID: &str = "RUSTSEC-2024-0001";
const HIGH_CVSS: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const LOW_CVSS: &str = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N";

struct Fixture {
    dir: TempDir,
}

impl Fixture {
    fn new(version: &str, cvss: Option<&str>) -> Self {
        let dir = TempDir::new().unwrap();
        let path = dir.path();
        fs::create_dir_all(path.join("db/crates/example")).unwrap();

        let cvss = cvss
            .map(|cvss| format!("cvss = \"{cvss}\"\n"))
            .unwrap_or_default();
        fs::write(
            path.join(format!("db/crates/example/{ID}.md")),
            format!(
                "```toml\n[advisory]\nid = \"{ID}\"\npackage = \"example\"\ndate = \"2024-01-01\"\n{cvss}\n[versions]\npatched = [\">= 0.2.0\"]\n```\n\n# Test advisory\n\nOffline fixture.\n"
            ),
        )
        .unwrap();

        fs::write(
            path.join("Cargo.lock"),
            format!(
                "version = 3\n\n[[package]]\nname = \"example\"\nversion = \"{version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            ),
        )
        .unwrap();

        fs::create_dir(path.join(".cargo")).unwrap();
        fs::write(path.join(".cargo/audit.toml"), "").unwrap();
        Self { dir }
    }

    fn high() -> Self {
        Self::new("0.1.0", Some(HIGH_CVSS))
    }

    fn low() -> Self {
        Self::new("0.1.0", Some(LOW_CVSS))
    }

    fn clean() -> Self {
        Self::new("0.2.0", Some(HIGH_CVSS))
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn config(&self, text: &str) {
        fs::write(self.path().join(".cargo/audit.toml"), text).unwrap();
    }

    fn config_text(&self) -> String {
        fs::read_to_string(self.path().join(".cargo/audit.toml")).unwrap()
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cargo-audit"))
            .current_dir(self.path())
            .args([
                "audit",
                "--db",
                "db",
                "--no-fetch",
                "--no-yanked",
                "--color",
                "never",
            ])
            .args(args)
            .output()
            .unwrap()
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn cvss_threshold_blocks_high_scores_and_allows_low_scores() {
    let high = Fixture::high();
    let output = high.run(&["--cvss-threshold", "7.0"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));

    let low = Fixture::low();
    let output = low.run(&["--cvss-threshold", "7.0"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let output = high.run(&["--cvss-threshold", "10.0"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn qualitative_and_numeric_thresholds_can_be_combined() {
    let high = Fixture::high();
    let output = high.run(&["--severity-threshold", "critical"]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));

    let low = Fixture::low();
    let output = low.run(&["--severity-threshold", "high"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let output = high.run(&[
        "--severity-threshold",
        "critical",
        "--cvss-threshold",
        "10.0",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn gate_blocks_dangerous_and_allows_exempted_projects() {
    let vulnerable = Fixture::high();
    let output = vulnerable.run(&["--cvss-threshold", "7.0", "--exit-code", "7"]);
    assert_eq!(output.status.code(), Some(7), "{}", stderr(&output));

    let exempted = Fixture::high();
    exempted.config(&format!(
        "[advisories]\nignore = [\"{ID}\"]\nwarn_unused_ignores = false\n"
    ));
    let output = exempted.run(&["--cvss-threshold", "7.0", "--exit-code", "7"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let safe = Fixture::clean();
    let output = safe.run(&["--cvss-threshold", "7.0", "--exit-code", "7"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn save_ignores_persists_rules_for_later_audits() {
    let fixture = Fixture::high();
    let output = fixture.run(&["--cvss-threshold", "7.0", "--ignore", ID, "--save-ignores"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(fixture.config_text().contains(ID));

    let output = fixture.run(&["--cvss-threshold", "7.0"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let output = fixture.run(&["--cvss-threshold", "7.0", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["vulnerabilities"]["count"], 0);
}

#[test]
fn ignore_file_and_custom_exit_codes_are_honored() {
    let fixture = Fixture::high();
    fs::write(
        fixture.path().join("ignores.txt"),
        format!("# waived\n{ID}\n"),
    )
    .unwrap();

    let output = fixture.run(&["--cvss-threshold", "7.0", "--ignore-file", "ignores.txt"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let output = fixture.run(&[
        "--cvss-threshold",
        "7.0",
        "--exit-code",
        "42",
        "--error-exit-code",
        "43",
    ]);
    assert_eq!(output.status.code(), Some(42), "{}", stderr(&output));

    let output = fixture.run(&["--file", "missing.lock", "--error-exit-code", "43"]);
    assert_eq!(output.status.code(), Some(43), "{}", stderr(&output));
}

#[test]
fn warn_policy_reports_without_failing_ci() {
    let fixture = Fixture::high();
    let output = fixture.run(&[
        "--cvss-threshold",
        "7.0",
        "--exit-code-policy",
        "warn",
        "--exit-code",
        "9",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stderr(&output).contains("vulnerability found"));
}

#[test]
fn config_supports_cvss_threshold_and_exit_policy() {
    let fixture = Fixture::high();
    fixture.config(
        "[advisories]\ncvss_threshold = 7.0\n\n[output]\nexit_code_policy = \"warn\"\nexit_code = 5\n",
    );

    let output = fixture.run(&[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    fixture.config("[advisories]\ncvss_threshold = 7.0\n\n[output]\nexit_code = 5\n");
    let output = fixture.run(&[]);
    assert_eq!(output.status.code(), Some(5), "{}", stderr(&output));
}

#[test]
fn persisted_ignore_file_can_be_reused() {
    let fixture = Fixture::high();
    let ignore_file = PathBuf::from("waivers.txt");

    let output = fixture.run(&[
        "--cvss-threshold",
        "7.0",
        "--ignore",
        ID,
        "--save-ignores",
        ignore_file.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(fixture.path().join(&ignore_file).exists());

    let output = fixture.run(&[
        "--cvss-threshold",
        "7.0",
        "--ignore-file",
        ignore_file.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn ignore_file_can_be_configured_persistently() {
    let fixture = Fixture::high();
    fs::write(fixture.path().join("waivers.txt"), format!("{ID}\n")).unwrap();
    fixture.config("[advisories]\nignore_file = \"waivers.txt\"\n");

    let output = fixture.run(&["--cvss-threshold", "7.0"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[test]
fn setup_errors_use_the_configured_error_exit_code() {
    let dir = TempDir::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cargo-audit"))
        .current_dir(dir.path())
        .args([
            "audit",
            "--db",
            "missing-db",
            "--no-fetch",
            "--error-exit-code",
            "43",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(43), "{}", stderr(&output));
}
