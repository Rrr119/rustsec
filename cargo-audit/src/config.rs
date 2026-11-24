//! The configuration file

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use rustsec::{WarningKind, advisory, report};
use serde::{Deserialize, Serialize};

use crate::{
    commands::AuditCommand,
    error::{Error, ErrorKind},
};

/// `cargo audit` configuration:
///
/// An optional TOML config file located in `~/.cargo/audit.toml` or
/// `.cargo/audit.toml`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Advisory-related configuration
    #[serde(default)]
    pub advisories: AdvisoryConfig,

    /// Advisory Database configuration
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Output configuration
    #[serde(default)]
    pub output: OutputConfig,

    /// Target-related configuration
    #[serde(default)]
    pub target: TargetConfig,

    /// Configuration for auditing for yanked crates
    #[serde(default)]
    pub yanked: YankedConfig,
}

impl AuditConfig {
    /// Load `audit.toml` (if it exists), overriding it with command-line arguments
    pub fn load(cli: &AuditCommand) -> Result<Self, Error> {
        // Check if the config file exists, and if it does not, ignore it.
        //
        // The order of precedence for which config file to use is:
        // 1. The current project's `.cargo` configuration directory.
        // 2. The current user's home directory configuration.

        let mut base = None;
        if let Ok(home) = home::cargo_home() {
            let home_config = home.join(CONFIG_FILE);
            if home_config.exists() {
                base = Some(home.join(CONFIG_FILE));
            }
        };

        let project_config_filename = PathBuf::from("./.cargo").join(CONFIG_FILE);
        if project_config_filename.exists() {
            base = Some(project_config_filename);
        }

        let mut config = match base {
            Some(path) => {
                let toml_string = fs::read_to_string(&path).map_err(|e| {
                    ErrorKind::Config.context(format!("couldn't read {}: {e}", path.display()))
                })?;
                toml::from_str(&toml_string).map_err(|e| ErrorKind::Parse.context(e))?
            }
            None => Self::default(),
        };

        if let Some(cvss_threshold) = config.advisories.cvss_threshold {
            validate_cvss_threshold(cvss_threshold)?;
        }

        if let Some(ignore_file) = config.advisories.ignore_file.clone() {
            let ignore_file = resolve_ignore_file(&ignore_file);
            config
                .advisories
                .ignore
                .extend(load_ignore_file(&ignore_file)?);
        }

        config.apply(cli)?;
        Ok(config)
    }

    /// Apply overrides from CLI options
    pub fn apply(&mut self, cli: &AuditCommand) -> Result<(), Error> {
        if let Some(db) = &cli.db {
            self.database.path = Some(db.into());
        }

        for advisory_id in &cli.ignore {
            self.advisories.ignore.push(
                advisory_id
                    .parse()
                    .map_err(|e| ErrorKind::Parse.context(e))?,
            );
        }

        if let Some(warn) = cli.warn_unused_ignores {
            self.advisories.warn_unused_ignores = warn;
        }

        if let Some(severity) = cli.severity_threshold {
            self.advisories.severity_threshold = Some(severity);
        }

        if let Some(cvss_threshold) = cli.cvss_threshold {
            validate_cvss_threshold(cvss_threshold)?;
            self.advisories.cvss_threshold = Some(cvss_threshold);
        }

        if let Some(ignore_file) = &cli.ignore_file {
            self.advisories
                .ignore
                .extend(load_ignore_file(&resolve_ignore_file(ignore_file))?);
        }

        self.database.fetch &= !cli.no_fetch;
        self.database.stale |= cli.stale;

        if !cli.target_arch.is_empty() {
            self.target.arch = Some(FilterList::Many(cli.target_arch.clone()));
        }

        if !cli.target_os.is_empty() {
            self.target.os = Some(FilterList::Many(cli.target_os.clone()));
        }

        if let Some(url) = &cli.url {
            self.database.url = Some(url.clone())
        }

        for kind in &cli.deny {
            if *kind == DenyOption::Warnings {
                self.output.deny = DenyOption::all();
            } else {
                self.output.deny.push(*kind);
            }
        }

        self.output.quiet |= cli.quiet;
        if cli.quiet {
            self.output.show_tree = false;
        }

        // Handle output format (--json flag takes precedence for backward compatibility)
        if cli.output_json {
            self.output.format = OutputFormat::Json;
        } else if let Some(format) = cli.output_format {
            self.output.format = format;
        }

        if cli.no_yanked {
            self.yanked.enabled = false;
        }

        if let Some(policy) = cli.exit_code_policy {
            self.output.exit_code_policy = policy;
        }

        if let Some(code) = cli.exit_code {
            self.output.failure_exit_code = code;
        }

        if let Some(code) = cli.error_exit_code {
            self.output.error_exit_code = code;
        }

        let mut seen = HashSet::new();
        self.advisories
            .ignore
            .retain(|advisory_id| seen.insert(advisory_id.clone()));

        Ok(())
    }

    /// Get audit report settings from the configuration
    pub fn report_settings(&self) -> report::Settings {
        let mut settings = report::Settings {
            ignore: self.advisories.ignore.clone(),
            severity: self.advisories.severity_threshold,
            cvss_threshold: self.advisories.cvss_threshold,
            target_arch: self.target.arch(),
            target_os: self.target.os(),
            ..Default::default()
        };

        if let Some(informational_warnings) = &self.advisories.informational_warnings {
            settings
                .informational_warnings
                .clone_from(informational_warnings);
        } else {
            // Alert for all informational packages by default
            settings.informational_warnings = vec![
                advisory::Informational::Unmaintained,
                advisory::Informational::Unsound,
                advisory::Informational::Notice,
            ];
        }

        // Enable warnings for all informational advisories if they are marked deny.
        // Deny only works on the output if a corresponding advisory is found but only the
        // informational categories listed in informational_warnings are reported.
        // This means that if "Unsound" is missing from informational_warnings then deny unsound
        // will not do anything.
        // To fix this always add the corresponding warning category
        let mut insert_if_not_present = |warning| {
            if !settings.informational_warnings.contains(&warning) {
                settings.informational_warnings.push(warning);
            }
        };

        for deny in &self.output.deny {
            match deny {
                DenyOption::Warnings => {
                    insert_if_not_present(advisory::Informational::Notice);
                    insert_if_not_present(advisory::Informational::Unmaintained);
                    insert_if_not_present(advisory::Informational::Unsound);
                    break;
                }
                DenyOption::Unmaintained => {
                    insert_if_not_present(advisory::Informational::Unmaintained)
                }
                DenyOption::Unsound => insert_if_not_present(advisory::Informational::Unsound),
                DenyOption::Yanked => continue,
            };
        }

        settings
    }
}

/// Advisory-related configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryConfig {
    /// Ignore advisories for the given IDs
    #[serde(default)]
    pub ignore: Vec<advisory::Id>,

    /// Warn when ignored advisories no longer affect the audited lockfile
    /// (default: true)
    #[serde(default = "default_true")]
    pub warn_unused_ignores: bool,

    /// Warn for the given types of informational advisories
    pub informational_warnings: Option<Vec<advisory::Informational>>,

    /// CVSS Qualitative Severity Rating Scale threshold to alert at.
    ///
    /// Vulnerabilities with explicit CVSS info which have a severity below
    /// this threshold will be ignored.
    pub severity_threshold: Option<advisory::Severity>,

    /// Numeric CVSS base score threshold to alert at.
    ///
    /// Vulnerabilities with explicit CVSS info which have a score below this
    /// threshold will be ignored. This can be combined with
    /// `severity_threshold`.
    #[serde(default, alias = "cvss_score_threshold")]
    pub cvss_threshold: Option<f64>,

    /// Optional file containing additional advisory IDs to ignore.
    ///
    /// The file can contain one ID per line, or TOML with a top-level
    /// `ignore` array or an `[advisories]` table containing `ignore`.
    #[serde(default)]
    pub ignore_file: Option<PathBuf>,
}

impl Default for AdvisoryConfig {
    fn default() -> Self {
        Self {
            ignore: Vec::new(),
            warn_unused_ignores: true,
            informational_warnings: None,
            severity_threshold: None,
            cvss_threshold: None,
            ignore_file: None,
        }
    }
}

/// Advisory Database configuration.
///
/// The advisory database is stored in a Git repository. This section of the
/// configuration stores settings related to it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Path to the local copy of advisory database's git repo (default: ~/.cargo/advisory-db)
    pub path: Option<PathBuf>,

    /// URL to the advisory database's git repo (default: <https://github.com/RustSec/advisory-db>)
    pub url: Option<String>,

    /// Perform a `git fetch` before auditing (default: true)
    #[serde(default = "default_true")]
    pub fetch: bool,

    /// Allow a stale advisory database? (i.e. one which hasn't been updated in 90 days)
    pub stale: bool,
}

impl DatabaseConfig {
    pub(crate) fn url(&self) -> &str {
        self.url
            .as_ref()
            .map(AsRef::as_ref)
            .unwrap_or(rustsec::repository::git::DEFAULT_URL)
    }

    pub(crate) fn path(&self) -> PathBuf {
        self.path
            .as_ref()
            .cloned()
            .unwrap_or_else(rustsec::repository::git::Repository::default_path)
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: None,
            url: None,
            fetch: true,
            stale: false,
        }
    }
}

/// Output configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    /// Disallow advisories which trigger warnings
    #[serde(default)]
    pub deny: Vec<DenyOption>,

    /// Output format to use
    #[serde(default)]
    pub format: OutputFormat,

    /// Enable quiet mode
    #[serde(default)]
    pub quiet: bool,

    /// Show inverse dependency trees along with advisories (default: true)
    #[serde(default = "default_show_tree")]
    pub show_tree: bool,

    /// How findings should be mapped to the process exit code
    #[serde(default)]
    pub exit_code_policy: ExitCodePolicy,

    /// Exit code used when the configured policy is violated
    #[serde(
        default = "default_failure_exit_code",
        alias = "exit_code",
        alias = "vulnerability_exit_code"
    )]
    pub failure_exit_code: u8,

    /// Exit code used when the audit cannot be completed
    #[serde(default = "default_error_exit_code", alias = "audit_error_exit_code")]
    pub error_exit_code: u8,
}

impl OutputConfig {
    /// Is quiet mode enabled?
    pub fn is_quiet(&self) -> bool {
        self.quiet || self.format == OutputFormat::Json || self.format == OutputFormat::Sarif
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            deny: Vec::new(),
            format: OutputFormat::default(),
            quiet: false,
            show_tree: default_show_tree(),
            exit_code_policy: ExitCodePolicy::default(),
            failure_exit_code: default_failure_exit_code(),
            error_exit_code: default_error_exit_code(),
        }
    }
}

fn default_show_tree() -> bool {
    true
}

fn default_failure_exit_code() -> u8 {
    1
}

fn default_error_exit_code() -> u8 {
    2
}

/// Policy for mapping audit findings to a process exit code.
#[derive(Default, Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExitCodePolicy {
    /// Fail on vulnerabilities and explicitly denied warnings
    #[default]
    #[serde(
        alias = "fail",
        alias = "block",
        alias = "deny",
        alias = "enforce",
        alias = "error"
    )]
    Default,

    /// Fail on vulnerabilities and every warning, even if it was not denied
    #[serde(alias = "all")]
    Strict,

    /// Report findings but never fail because of them
    #[serde(
        alias = "warning",
        alias = "warn-only",
        alias = "none",
        alias = "never",
        alias = "ignore",
        alias = "allow",
        alias = "pass",
        alias = "success"
    )]
    Warn,
}

impl FromStr for ExitCodePolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_ascii_lowercase().as_str() {
            "default" | "fail" | "block" | "deny" | "enforce" | "error" => Ok(Self::Default),
            "strict" | "all" => Ok(Self::Strict),
            "warn" | "warning" | "warn-only" | "none" | "never" | "ignore" | "allow" | "pass"
            | "success" => Ok(Self::Warn),
            other => Err(ErrorKind::Parse.context(format!("invalid exit code policy: {other}"))),
        }
    }
}

/// Warning kinds
#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Serialize, Ord)]
pub enum DenyOption {
    /// Deny all warnings
    #[serde(rename = "warnings")]
    Warnings,

    /// Deny unmaintained dependency warnings
    #[serde(rename = "unmaintained")]
    Unmaintained,

    /// Deny unsound dependency warnings
    #[serde(rename = "unsound")]
    Unsound,

    /// Deny yanked dependency warnings
    #[serde(rename = "yanked")]
    Yanked,
}

impl DenyOption {
    /// Get all of the possible warnings to be denied
    pub fn all() -> Vec<Self> {
        vec![
            Self::Warnings,
            Self::Unmaintained,
            Self::Unsound,
            Self::Yanked,
        ]
    }
    /// Get the warning::Kind that corresponds to self, if applicable
    pub fn get_warning_kind(self) -> &'static [WarningKind] {
        match self {
            Self::Warnings => &[
                WarningKind::Unmaintained,
                WarningKind::Unsound,
                WarningKind::Yanked,
            ],
            Self::Unmaintained => &[WarningKind::Unmaintained],
            Self::Unsound => &[WarningKind::Unsound],
            Self::Yanked => &[WarningKind::Yanked],
        }
    }
}

impl FromStr for DenyOption {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "warnings" => Ok(Self::Warnings),
            "unmaintained" => Ok(Self::Unmaintained),
            "unsound" => Ok(Self::Unsound),
            "yanked" => Ok(Self::Yanked),
            other => Err(ErrorKind::Parse.context(format!("invalid deny option: {other}"))),
        }
    }
}

/// Output format
#[derive(Default, Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, clap::ValueEnum)]
pub enum OutputFormat {
    /// Display JSON
    #[serde(rename = "json")]
    Json,

    /// Display SARIF (Static Analysis Results Interchange Format)
    #[serde(rename = "sarif")]
    Sarif,

    /// Display human-readable output to the terminal
    #[serde(rename = "terminal")]
    #[default]
    Terminal,
}

impl FromStr for OutputFormat {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "json" => Ok(Self::Json),
            "sarif" => Ok(Self::Sarif),
            "terminal" => Ok(Self::Terminal),
            other => Err(ErrorKind::Parse.context(format!("invalid output format: {other}"))),
        }
    }
}

/// Helper enum for configuring filter values
///
/// This enum exists for backwards compatibility reasons.
/// In `cargo-audit` versions `<= 0.20.0` target's config
/// options `arch` and `os` were deserialized from a single
/// string. But following next minor release those values can be
/// configured as a list. Serde's untagged enum provides
/// dispatch that is backwards compatible.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FilterList<T> {
    /// Legacy, single filter value
    Single(T),
    /// List of filters
    Many(Vec<T>),
}

/// Target configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    /// Target architecture to find vulnerabilities for
    pub arch: Option<FilterList<String>>,

    /// Target OS to find vulnerabilities for
    pub os: Option<FilterList<String>>,
}

impl TargetConfig {
    /// Returns list of configured target architectures, cloning if needed
    pub fn arch(&self) -> Vec<String> {
        match &self.arch {
            Some(FilterList::Single(single)) => vec![single.clone()],
            Some(FilterList::Many(many)) => many.clone(),
            None => vec![],
        }
    }

    /// Returns list of configured target operating systems, cloning if needed
    pub fn os(&self) -> Vec<String> {
        match &self.os {
            Some(FilterList::Single(single)) => vec![single.clone()],
            Some(FilterList::Many(many)) => many.clone(),
            None => vec![],
        }
    }
}

/// Configuration for auditing for yanked crates
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct YankedConfig {
    /// Is auditing for yanked crates enabled?
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Should the crates.io index be updated before checking for yanked crates?
    #[serde(default = "default_true")]
    pub update_index: bool,
}

impl Default for YankedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            update_index: true,
        }
    }
}

/// Helper function for returning a default of `true`
fn default_true() -> bool {
    true
}

/// Name of the configuration file
///
/// This file allows setting some default auditing options.
const CONFIG_FILE: &str = "audit.toml";

/// Validate a numeric CVSS threshold.
pub fn validate_cvss_threshold(threshold: f64) -> Result<(), Error> {
    if threshold.is_nan() || !(0.0..=10.0).contains(&threshold) {
        return Err(ErrorKind::Config.context(format!(
            "CVSS threshold must be between 0.0 and 10.0, got {threshold}"
        )));
    }
    Ok(())
}

/// Load advisory IDs from an ignore file.
///
/// Files may contain one advisory ID per line, or TOML with a top-level
/// `ignore` array or an `[advisories]` table containing `ignore`.
pub fn load_ignore_file(path: &Path) -> Result<Vec<advisory::Id>, Error> {
    let text = fs::read_to_string(path).map_err(|e| {
        ErrorKind::Config.context(format!("couldn't read ignore file {}: {e}", path.display()))
    })?;

    #[derive(Debug, Default, Deserialize)]
    struct IgnoreFile {
        #[serde(default)]
        ignore: Vec<advisory::Id>,
        advisories: Option<IgnoreSection>,
    }

    #[derive(Debug, Default, Deserialize)]
    struct IgnoreSection {
        #[serde(default)]
        ignore: Vec<advisory::Id>,
    }

    if let Ok(ignore_file) = toml::from_str::<IgnoreFile>(&text) {
        let mut ids = ignore_file.ignore;
        if let Some(advisories) = ignore_file.advisories {
            ids.extend(advisories.ignore);
        }
        return Ok(ids);
    }

    let mut ids = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default();
        for token in line.split(|c: char| c == ',' || c.is_whitespace()) {
            if token.is_empty() {
                continue;
            }
            ids.push(token.parse().map_err(|e| ErrorKind::Parse.context(e))?);
        }
    }
    Ok(ids)
}

/// Persist ignore rules so they are used by subsequent audits.
///
/// If `target` is `None` or empty, the project-local `.cargo/audit.toml` is
/// updated. Files ending in `.toml` are treated as audit configuration files,
/// while other paths are written as a plain list of advisory IDs.
pub fn persist_ignores(target: Option<&Path>, ignores: &[advisory::Id]) -> Result<PathBuf, Error> {
    let path = match target {
        Some(target) if !target.as_os_str().is_empty() => target.to_path_buf(),
        _ => PathBuf::from(".cargo").join(CONFIG_FILE),
    };

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            ErrorKind::Io.context(format!(
                "couldn't create directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    if path
        .extension()
        .is_some_and(|extension| extension == "toml")
    {
        persist_ignores_to_config(&path, ignores)?;
    } else {
        let mut contents = ignores
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        if !contents.is_empty() {
            contents.push('\n');
        }
        fs::write(&path, contents).map_err(|e| {
            ErrorKind::Io.context(format!("couldn't write {}: {e}", path.display()))
        })?;
    }

    Ok(path)
}

fn persist_ignores_to_config(path: &Path, ignores: &[advisory::Id]) -> Result<(), Error> {
    let existing = if path.exists() {
        fs::read_to_string(path).map_err(|e| {
            ErrorKind::Config.context(format!("couldn't read {}: {e}", path.display()))
        })?
    } else {
        String::new()
    };

    let mut document = existing
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| ErrorKind::Parse.context(e))?;

    let advisories = document
        .entry("advisories")
        .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let advisories = advisories
        .as_table_mut()
        .ok_or_else(|| ErrorKind::Config.context("`advisories` in audit.toml must be a table"))?;

    let mut array = toml_edit::Array::new();
    for id in ignores {
        array.push(id.to_string());
    }
    advisories.insert("ignore", toml_edit::value(array));

    fs::write(path, document.to_string())
        .map_err(|e| ErrorKind::Io.context(format!("couldn't write {}: {e}", path.display())))
}

fn resolve_ignore_file(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        PathBuf::from(".").join(path)
    }
}
