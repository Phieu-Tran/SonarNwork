use anyhow::{bail, ensure, Context, Result};
use reqwest::blocking::Client;
use serde::Deserialize;
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const REPOSITORY: &str = "Phieu-Tran/SonarNwork";
const MAX_RELEASE_ASSET_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpdateChannel {
    Scoop,
    Winget,
    Cargo,
    WindowsPortable,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Debian,
    Unsupported,
}

pub fn run(check_only: bool, confirmed: bool) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let release = latest_release()?;
    let ordering = compare_release_versions(current, &release.tag_name)?;

    match ordering {
        Ordering::Less => {
            println!("Current version: v{current}");
            println!("Latest version : {}", release.tag_name);
        }
        Ordering::Equal => {
            println!("SonarNwork is up to date (v{current}).");
            return Ok(());
        }
        Ordering::Greater => {
            println!(
                "Current version v{current} is newer than the latest published release {}.",
                release.tag_name
            );
            return Ok(());
        }
    }

    if check_only {
        println!("Run `sonar update` to install the latest version.");
        return Ok(());
    }

    confirm_update(&release.tag_name, confirmed)?;
    let executable = env::current_exe().context("resolve the current SonarNwork executable")?;
    let channel = update_channel(&executable);
    println!("Update channel : {}", channel_label(channel));

    match channel {
        UpdateChannel::Scoop => run_program("scoop", ["update", "sonarnwork"]),
        UpdateChannel::Winget => run_program(
            "winget",
            [
                "upgrade",
                "--id",
                "PhieuTran.SonarNwork",
                "--exact",
                "--accept-source-agreements",
                "--accept-package-agreements",
            ],
        ),
        UpdateChannel::Cargo => run_program(
            "cargo",
            [
                "install",
                "--git",
                "https://github.com/Phieu-Tran/SonarNwork.git",
                "--locked",
                "--package",
                "sonar-cli",
            ],
        ),
        UpdateChannel::WindowsPortable => start_windows_portable_update(&release, &executable),
        UpdateChannel::Debian => update_debian_package(&release),
        UpdateChannel::Unsupported => bail!(
            "this installation location cannot be updated safely; reinstall from GitHub Releases or use a supported package manager"
        ),
    }
}

fn latest_release() -> Result<GithubRelease> {
    let client = github_client()?;
    client
        .get(format!(
            "https://api.github.com/repos/{REPOSITORY}/releases/latest"
        ))
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .context("get the latest SonarNwork release")?
        .json()
        .context("read the latest SonarNwork release metadata")
}

fn github_client() -> Result<Client> {
    Client::builder()
        .user_agent(format!("SonarNwork/{} updater", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("create the release update client")
}

fn confirm_update(version: &str, confirmed: bool) -> Result<()> {
    if confirmed {
        return Ok(());
    }

    ensure!(
        io::stdin().is_terminal(),
        "an update is available; rerun with `sonar update --yes` to install it non-interactively"
    );
    print!("Install SonarNwork {version}? [y/N] ");
    io::stdout().flush().context("flush update confirmation")?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("read update confirmation")?;
    ensure!(
        matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        "update cancelled"
    );
    Ok(())
}

fn update_channel(executable: &Path) -> UpdateChannel {
    let path = executable
        .to_string_lossy()
        .replace(['/', '\\'], "\\")
        .to_ascii_lowercase();

    if path.contains("\\scoop\\apps\\sonarnwork\\") {
        return UpdateChannel::Scoop;
    }
    if path.contains("\\microsoft\\winget\\packages\\phieutran.sonarnwork_") {
        return UpdateChannel::Winget;
    }
    if path.contains("\\.cargo\\bin\\") {
        return UpdateChannel::Cargo;
    }
    if path.contains("\\target\\debug\\") || path.contains("\\target\\release\\") {
        return UpdateChannel::Unsupported;
    }

    #[cfg(windows)]
    {
        UpdateChannel::WindowsPortable
    }

    #[cfg(target_os = "linux")]
    {
        if executable.starts_with("/usr/bin/") {
            UpdateChannel::Debian
        } else {
            UpdateChannel::Unsupported
        }
    }

    #[cfg(not(any(windows, target_os = "linux")))]
    {
        UpdateChannel::Unsupported
    }
}

fn channel_label(channel: UpdateChannel) -> &'static str {
    match channel {
        UpdateChannel::Scoop => "Scoop",
        UpdateChannel::Winget => "WinGet",
        UpdateChannel::Cargo => "Cargo",
        UpdateChannel::WindowsPortable => "portable bundle",
        UpdateChannel::Debian => "Debian package",
        UpdateChannel::Unsupported => "unsupported",
    }
}

fn run_program<const N: usize>(program: &str, args: [&str; N]) -> Result<()> {
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("start {program}"))?;
    ensure!(status.success(), "{program} update exited with {status}");
    println!("Update completed. Open a new terminal before running SonarNwork again.");
    Ok(())
}

#[cfg(windows)]
fn start_windows_portable_update(release: &GithubRelease, executable: &Path) -> Result<()> {
    let installer = release.asset("install.ps1")?;
    let bytes = download_asset(&github_client()?, installer)?;
    let script_path = env::temp_dir().join(format!("sonarnwork-update-{}.ps1", std::process::id()));
    fs::write(&script_path, bytes).context("stage the SonarNwork updater")?;
    let install_root = executable
        .parent()
        .context("resolve the portable SonarNwork directory")?;

    Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script_path)
        .arg("-InstallRoot")
        .arg(install_root)
        .arg("-WaitForProcessId")
        .arg(std::process::id().to_string())
        .spawn()
        .context("start the portable SonarNwork updater")?;

    println!(
        "SonarNwork is closing so the updater can replace the portable bundle. Open a new terminal when it finishes."
    );
    Ok(())
}

#[cfg(not(windows))]
fn start_windows_portable_update(_: &GithubRelease, _: &Path) -> Result<()> {
    bail!("the portable Windows updater is only available on Windows")
}

#[cfg(target_os = "linux")]
fn update_debian_package(release: &GithubRelease) -> Result<()> {
    let version = release.version()?;
    let package_name = format!("SonarNwork-{version}-linux-x64.deb");
    let package = release.asset(&package_name)?;
    let checksums = release.asset("SHA256SUMS.txt")?;
    let client = github_client()?;
    let expected_hash = expected_checksum(&download_asset(&client, checksums)?, &package_name)?;
    let package_bytes = download_asset(&client, package)?;
    let actual_hash = format!("{:x}", Sha256::digest(&package_bytes));
    ensure!(
        actual_hash == expected_hash,
        "SHA-256 verification failed for {package_name}"
    );

    let path = env::temp_dir().join(&package_name);
    fs::write(&path, package_bytes).context("stage the Debian package update")?;
    let status = Command::new("sudo")
        .args(["apt", "install", "--yes"])
        .arg(&path)
        .status()
        .context("start the Debian package update")?;
    let _ = fs::remove_file(&path);
    ensure!(
        status.success(),
        "Debian package update exited with {status}"
    );
    println!("Update completed. Restart SonarNwork to use the new version.");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn update_debian_package(_: &GithubRelease) -> Result<()> {
    bail!("the Debian updater is only available on Linux")
}

impl GithubRelease {
    fn asset(&self, name: &str) -> Result<&GithubAsset> {
        self.assets
            .iter()
            .find(|asset| asset.name == name)
            .with_context(|| format!("find release asset {name}"))
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn version(&self) -> Result<&str> {
        self.tag_name
            .strip_prefix('v')
            .filter(|version| !version.is_empty())
            .context("the latest release tag must begin with v")
    }
}

fn download_asset(client: &Client, asset: &GithubAsset) -> Result<Vec<u8>> {
    ensure_allowed_asset_url(&asset.browser_download_url)?;
    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .with_context(|| format!("download release asset {}", asset.name))?
        .bytes()
        .with_context(|| format!("read release asset {}", asset.name))?;
    ensure!(
        bytes.len() <= MAX_RELEASE_ASSET_BYTES,
        "release asset {} is too large",
        asset.name
    );
    Ok(bytes.to_vec())
}

fn ensure_allowed_asset_url(url: &str) -> Result<()> {
    let prefix = format!("https://github.com/{REPOSITORY}/releases/download/");
    ensure!(
        url.starts_with(&prefix),
        "release asset URL is not allow-listed"
    );
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn expected_checksum(contents: &[u8], asset_name: &str) -> Result<String> {
    let contents = std::str::from_utf8(contents).context("read SHA256SUMS.txt as UTF-8")?;
    contents
        .lines()
        .find_map(|line| {
            let (hash, name) = line.split_once("  ")?;
            (name == asset_name).then_some(hash.to_ascii_lowercase())
        })
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .with_context(|| format!("find SHA-256 for {asset_name}"))
}

fn compare_release_versions(current: &str, latest_tag: &str) -> Result<Ordering> {
    let current = parse_version(current)?;
    let latest = parse_version(latest_tag)?;
    Ok(current.cmp(&latest))
}

#[derive(Debug, Eq, PartialEq)]
struct ReleaseVersion {
    components: Vec<u64>,
    prerelease: Option<String>,
}

impl Ord for ReleaseVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let width = self.components.len().max(other.components.len());
        for index in 0..width {
            let comparison = self
                .components
                .get(index)
                .copied()
                .unwrap_or_default()
                .cmp(&other.components.get(index).copied().unwrap_or_default());
            if comparison != Ordering::Equal {
                return comparison;
            }
        }

        match (&self.prerelease, &other.prerelease) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(left), Some(right)) => left.cmp(right),
        }
    }
}

impl PartialOrd for ReleaseVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn parse_version(value: &str) -> Result<ReleaseVersion> {
    let value = value.trim().strip_prefix('v').unwrap_or(value.trim());
    let value = value.split_once('+').map_or(value, |(version, _)| version);
    let (core, prerelease) = value
        .split_once('-')
        .map_or((value, None), |(core, prerelease)| (core, Some(prerelease)));
    let components = core
        .split('.')
        .map(|part| {
            part.parse::<u64>()
                .with_context(|| format!("invalid version {value}"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        components.len() >= 3 && prerelease.is_none_or(|value| !value.is_empty()),
        "invalid version {value}"
    );
    Ok(ReleaseVersion {
        components,
        prerelease: prerelease.map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_versions_compare_semantically() {
        assert_eq!(
            compare_release_versions("0.1.9", "v0.1.10").unwrap(),
            Ordering::Less
        );
        assert_eq!(
            compare_release_versions("0.2.0-rc.1", "v0.2.0").unwrap(),
            Ordering::Less
        );
        assert_eq!(
            compare_release_versions("0.2.0", "v0.2.0-rc.1").unwrap(),
            Ordering::Greater
        );
    }

    #[test]
    fn malformed_release_versions_are_rejected() {
        assert!(compare_release_versions("0.1", "v0.1.1").is_err());
        assert!(compare_release_versions("0.1.1", "latest").is_err());
    }

    #[test]
    fn checksum_lookup_requires_a_valid_exact_entry() {
        let checksum = expected_checksum(
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  SonarNwork-0.1.4-linux-x64.deb\n",
            "SonarNwork-0.1.4-linux-x64.deb",
        )
        .unwrap();
        assert_eq!(
            checksum,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(expected_checksum(b"not-a-checksum  other-file", "other-file").is_err());
    }

    #[test]
    fn release_asset_urls_must_remain_in_the_official_repository() {
        assert!(ensure_allowed_asset_url(
            "https://github.com/Phieu-Tran/SonarNwork/releases/download/v0.1.4/install.ps1"
        )
        .is_ok());
        assert!(ensure_allowed_asset_url("https://example.com/install.ps1").is_err());
    }
}
