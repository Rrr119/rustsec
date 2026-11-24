//! Configuration file tests

use std::{fs, path::Path};

use cargo_audit::config::{AuditConfig, ExitCodePolicy, OutputFormat};

#[test]
fn default_output_config() {
    let output = AuditConfig::default().output;
    assert!(output.show_tree);
    assert!(output.deny.is_empty());
    assert_eq!(output.format, OutputFormat::Terminal);
    assert!(!output.quiet);
}

#[test]
fn configured_dependency_trees() {
    for (input, show_tree) in [
        ("", true),
        ("[target]\narch = 'x86_64'", true),
        ("[output]\nquiet = false", true),
        ("[output]\nquiet = false\nshow_tree = true", true),
        ("[output]\nquiet = false\nshow_tree = false", false),
    ] {
        let config: AuditConfig = toml::from_str(input).unwrap();
        assert_eq!(config.output.show_tree, show_tree, "{input}");
    }
}

/// Ensure `audit.toml.example` parses as a valid config file
#[test]
fn parse_audit_toml_example() {
    let toml_string = fs::read_to_string("audit.toml.example").unwrap();
    let config: AuditConfig = toml::from_str(&toml_string).unwrap();

    assert_eq!(
        config.database.path.unwrap(),
        Path::new("~/.cargo/advisory-db")
    );
    assert_eq!(
        config.database.url.unwrap(),
        "https://github.com/RustSec/advisory-db.git"
    );
    assert_eq!(config.target.arch(), vec!["x86_64".to_owned()]);
    assert_eq!(
        config.target.os(),
        vec!["linux".to_owned(), "windows".to_owned()]
    );
}

/// Ensure `target.arch` and `target.os` continue to parse when they
/// are specified as a string, and not a list. This is the legacy behavior.
#[test]
fn parser_audit_toml_example() {
    let toml_string = fs::read_to_string("tests/audit.toml.legacy").unwrap();
    let config: AuditConfig = toml::from_str(&toml_string).unwrap();

    assert_eq!(config.target.arch(), vec!["x86_64".to_owned()]);
    assert_eq!(config.target.os(), vec!["linux".to_owned()]);
}

#[test]
fn parses_gating_configuration() {
    let config: AuditConfig = toml::from_str(
        r#"
        [advisories]
        cvss_threshold = 7.5
        ignore = ["RUSTSEC-2024-0001"]

        [output]
        exit_code_policy = "strict"
        exit_code = 10
        error_exit_code = 11
        "#,
    )
    .unwrap();

    assert_eq!(config.advisories.cvss_threshold, Some(7.5));
    assert_eq!(config.advisories.ignore.len(), 1);
    assert_eq!(config.output.exit_code_policy, ExitCodePolicy::Strict);
    assert_eq!(config.output.failure_exit_code, 10);
    assert_eq!(config.output.error_exit_code, 11);
}

#[test]
fn parses_exit_policy_aliases() {
    for (name, expected) in [
        ("default", ExitCodePolicy::Default),
        ("fail", ExitCodePolicy::Default),
        ("strict", ExitCodePolicy::Strict),
        ("warn", ExitCodePolicy::Warn),
        ("ignore", ExitCodePolicy::Warn),
    ] {
        let config: AuditConfig =
            toml::from_str(&format!("[output]\nexit_code_policy = \"{name}\"\n")).unwrap();
        assert_eq!(config.output.exit_code_policy, expected, "{name}");
    }
}
