use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    thread,
    time::Duration,
};

use reqwest::blocking::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::{Result, ToolError};

const GLOBALPING_API: &str = "https://api.globalping.io/v1";
const CHECK_HOST_API: &str = "https://check-host.net";
const MAX_REMOTE_RESULTS: usize = 3;
const MAX_RAW_OUTPUT: usize = 16 * 1024;
const POLL_ATTEMPTS: usize = 25;
const POLL_DELAY: Duration = Duration::from_millis(600);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GlobalpingMeasurementKind {
    Ping,
    Traceroute,
    Mtr,
    Dns,
    Http,
}

impl GlobalpingMeasurementKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Traceroute => "traceroute",
            Self::Mtr => "mtr",
            Self::Dns => "dns",
            Self::Http => "http",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlobalpingMeasurementRequest {
    pub kind: GlobalpingMeasurementKind,
    pub target: String,
    pub location: String,
    pub limit: u8,
    pub scope_confirmed: bool,
    pub token: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteNodeResult {
    pub location: String,
    pub network: Option<String>,
    pub status: String,
    pub summary: String,
    pub raw_output: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlobalpingMeasurementResult {
    pub provider: String,
    pub id: String,
    pub measurement: GlobalpingMeasurementKind,
    pub target: String,
    pub status: String,
    pub share_url: String,
    pub nodes: Vec<RemoteNodeResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemotePortCheckRequest {
    pub target: String,
    pub port: u16,
    pub max_nodes: u8,
    pub scope_confirmed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemotePortCheckResult {
    pub provider: String,
    pub id: String,
    pub target: String,
    pub port: u16,
    pub status: String,
    pub report_url: String,
    pub nodes: Vec<RemoteNodeResult>,
}

#[derive(Clone)]
pub struct RemoteProviderClient {
    client: Client,
    globalping_api: String,
    check_host_api: String,
}

impl RemoteProviderClient {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("SonarNwork/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(operation)?;
        Ok(Self {
            client,
            globalping_api: GLOBALPING_API.into(),
            check_host_api: CHECK_HOST_API.into(),
        })
    }

    #[cfg(test)]
    fn with_endpoints(globalping_api: String, check_host_api: String) -> Result<Self> {
        let mut client = Self::new()?;
        client.globalping_api = globalping_api;
        client.check_host_api = check_host_api;
        Ok(client)
    }

    pub fn run_globalping(
        &self,
        request: GlobalpingMeasurementRequest,
    ) -> Result<GlobalpingMeasurementResult> {
        if !request.scope_confirmed {
            return Err(ToolError::Operation(
                "remote measurement requires explicit target authorization".into(),
            ));
        }
        let limit = request.limit.clamp(1, MAX_REMOTE_RESULTS as u8);
        let (target, options) = globalping_target_and_options(request.kind, &request.target)?;
        validate_public_host(&target)?;

        let location = request.location.trim();
        let mut body = json!({
            "type": request.kind.as_str(),
            "target": target,
            "inProgressUpdates": false,
            "measurementOptions": options,
        });
        if location.is_empty() {
            body["limit"] = json!(limit);
        } else {
            body["locations"] = json!([{ "magic": location, "limit": limit }]);
        }

        let create_url = format!("{}/measurements", self.globalping_api);
        let create = send_json(globalping_auth(
            self.client.post(create_url).json(&body),
            request.token.as_deref(),
        ))?;
        let id = create
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                ToolError::Operation("Globalping response did not contain a measurement id".into())
            })?
            .to_string();

        let mut measurement = Value::Null;
        for _ in 0..POLL_ATTEMPTS {
            measurement = send_json(globalping_auth(
                self.client
                    .get(format!("{}/measurements/{id}", self.globalping_api)),
                request.token.as_deref(),
            ))?;
            if measurement.get("status").and_then(Value::as_str) != Some("in-progress") {
                break;
            }
            thread::sleep(POLL_DELAY);
        }

        let status = measurement
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let nodes = globalping_nodes(&measurement);
        Ok(GlobalpingMeasurementResult {
            provider: "globalping".into(),
            id: id.clone(),
            measurement: request.kind,
            target,
            status,
            share_url: format!("https://globalping.io?measurement={id}"),
            nodes,
        })
    }

    pub fn run_remote_port_check(
        &self,
        request: RemotePortCheckRequest,
    ) -> Result<RemotePortCheckResult> {
        if !request.scope_confirmed {
            return Err(ToolError::Operation(
                "remote port check requires explicit target authorization".into(),
            ));
        }
        let host = normalize_host(&request.target)?;
        validate_public_host(&host)?;
        let max_nodes = request.max_nodes.clamp(1, MAX_REMOTE_RESULTS as u8);
        let start = send_json(
            self.client
                .get(format!("{}/check-tcp", self.check_host_api))
                .header("Accept", "application/json")
                .query(&[
                    ("host", format_host_port(&host, request.port)),
                    ("max_nodes", max_nodes.to_string()),
                ]),
        )?;
        let id = start
            .get("request_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                ToolError::Operation("remote TCP provider did not return a request id".into())
            })?
            .to_string();
        let report_url = start
            .get("permanent_link")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let node_metadata = start.get("nodes").cloned().unwrap_or_else(|| json!({}));

        let mut report = Value::Null;
        for _ in 0..POLL_ATTEMPTS {
            report = send_json(
                self.client
                    .get(format!("{}/check-result/{id}", self.check_host_api))
                    .header("Accept", "application/json"),
            )?;
            if check_host_is_complete(
                &report,
                node_metadata.as_object().map_or(0, |nodes| nodes.len()),
            ) {
                break;
            }
            thread::sleep(POLL_DELAY);
        }

        let nodes = check_host_nodes(&node_metadata, &report);
        let reachable = nodes.iter().filter(|node| node.status == "open").count();
        let completed = nodes.iter().filter(|node| node.status != "pending").count();
        let status = if reachable > 0 {
            "open"
        } else if completed == nodes.len() && completed > 0 {
            "closed_or_filtered"
        } else {
            "in_progress"
        };
        Ok(RemotePortCheckResult {
            provider: "check_host".into(),
            id,
            target: host,
            port: request.port,
            status: status.into(),
            report_url,
            nodes,
        })
    }
}

fn globalping_auth(builder: RequestBuilder, token: Option<&str>) -> RequestBuilder {
    match token.map(str::trim).filter(|token| !token.is_empty()) {
        Some(token) => builder.bearer_auth(token),
        None => builder,
    }
}

fn send_json(builder: RequestBuilder) -> Result<Value> {
    let response = builder.send().map_err(operation)?;
    let status = response.status();
    let bytes = response.bytes().map_err(operation)?;
    if !status.is_success() {
        let detail = String::from_utf8_lossy(&bytes[..bytes.len().min(2048)]);
        return Err(ToolError::Operation(format!(
            "remote provider returned HTTP {status}: {}",
            detail.trim()
        )));
    }
    serde_json::from_slice(&bytes).map_err(operation)
}

fn globalping_target_and_options(
    kind: GlobalpingMeasurementKind,
    input: &str,
) -> Result<(String, Value)> {
    if kind != GlobalpingMeasurementKind::Http {
        return Ok((
            normalize_host(input)?,
            match kind {
                GlobalpingMeasurementKind::Ping => json!({ "packets": 3 }),
                GlobalpingMeasurementKind::Traceroute => json!({ "protocol": "ICMP" }),
                GlobalpingMeasurementKind::Mtr => json!({ "protocol": "ICMP", "packets": 3 }),
                GlobalpingMeasurementKind::Dns => {
                    json!({ "query": { "type": "A" }, "protocol": "UDP" })
                }
                GlobalpingMeasurementKind::Http => unreachable!(),
            },
        ));
    }

    let raw = input.trim();
    let url = if raw.contains("://") {
        Url::parse(raw)
    } else {
        Url::parse(&format!("https://{raw}"))
    }
    .map_err(|_| {
        ToolError::Operation("HTTP remote measurement requires a valid HTTP(S) URL or host".into())
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ToolError::Operation(
            "HTTP remote measurement accepts only http:// or https:// targets".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ToolError::Operation("remote target has no host".into()))?
        .to_string();
    let protocol = if url.scheme() == "http" {
        "HTTP"
    } else {
        "HTTPS"
    };
    let default_port = if protocol == "HTTP" { 80 } else { 443 };
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let mut request = json!({ "method": "HEAD", "path": path });
    if let Some(query) = url.query() {
        request["query"] = json!(query);
    }
    Ok((
        host,
        json!({
            "request": request,
            "port": url.port().unwrap_or(default_port),
            "protocol": protocol,
        }),
    ))
}

fn globalping_nodes(measurement: &Value) -> Vec<RemoteNodeResult> {
    measurement
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_REMOTE_RESULTS)
        .map(|item| {
            let probe = item.get("probe").unwrap_or(&Value::Null);
            let result = item.get("result").unwrap_or(&Value::Null);
            let city = probe
                .get("city")
                .and_then(Value::as_str)
                .unwrap_or("Unknown");
            let country = probe.get("country").and_then(Value::as_str).unwrap_or("--");
            let network = probe
                .get("network")
                .and_then(Value::as_str)
                .map(str::to_string);
            RemoteNodeResult {
                location: format!("{city}, {country}"),
                network,
                status: result
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                summary: summarize_globalping_result(result),
                raw_output: result
                    .get("rawOutput")
                    .and_then(Value::as_str)
                    .map(limit_raw),
            }
        })
        .collect()
}

fn summarize_globalping_result(result: &Value) -> String {
    if let Some(stats) = result.get("stats") {
        let avg = stats.get("avg").and_then(Value::as_f64);
        let loss = stats.get("loss").and_then(Value::as_f64);
        if avg.is_some() || loss.is_some() {
            return format!(
                "avg {} ms, loss {}%",
                display_number(avg),
                display_number(loss)
            );
        }
    }
    if let Some(code) = result.get("statusCode").and_then(Value::as_i64) {
        let name = result
            .get("statusCodeName")
            .and_then(Value::as_str)
            .unwrap_or("");
        return format!("status {code} {name}").trim().to_string();
    }
    if let Some(hops) = result.get("hops").and_then(Value::as_array) {
        return format!("{} hop(s)", hops.len());
    }
    result
        .get("rawOutput")
        .and_then(Value::as_str)
        .and_then(|raw| raw.lines().find(|line| !line.trim().is_empty()))
        .map(|line| limit_raw(line.trim()))
        .unwrap_or_else(|| {
            result
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("No result detail")
                .to_string()
        })
}

fn check_host_is_complete(report: &Value, expected: usize) -> bool {
    let Some(values) = report.as_object() else {
        return false;
    };
    expected > 0 && values.len() >= expected && values.values().all(|value| !value.is_null())
}

fn check_host_nodes(metadata: &Value, report: &Value) -> Vec<RemoteNodeResult> {
    let Some(nodes) = metadata.as_object() else {
        return Vec::new();
    };
    nodes
        .iter()
        .take(MAX_REMOTE_RESULTS)
        .map(|(node_id, location)| {
            let parts = location.as_array();
            let country = parts
                .and_then(|parts| parts.get(1))
                .and_then(Value::as_str)
                .unwrap_or("Unknown");
            let city = parts
                .and_then(|parts| parts.get(2))
                .and_then(Value::as_str)
                .unwrap_or(node_id);
            let network = parts
                .and_then(|parts| parts.get(4))
                .and_then(Value::as_str)
                .map(str::to_string);
            let value = report.get(node_id).unwrap_or(&Value::Null);
            let (status, summary) = summarize_check_host_value(value);
            RemoteNodeResult {
                location: format!("{city}, {country}"),
                network,
                status,
                summary,
                raw_output: None,
            }
        })
        .collect()
}

fn summarize_check_host_value(value: &Value) -> (String, String) {
    if value.is_null() {
        return ("pending".into(), "Waiting for remote node".into());
    }
    let entries = value.as_array().into_iter().flatten();
    for entry in entries {
        if let Some(error) = entry.get("error").and_then(Value::as_str) {
            return ("closed_or_filtered".into(), error.to_string());
        }
        if let Some(time) = entry.get("time").and_then(Value::as_f64) {
            let address = entry.get("address").and_then(Value::as_str).unwrap_or("");
            return (
                "open".into(),
                format!("connected to {address} in {:.0} ms", time * 1000.0),
            );
        }
    }
    (
        "closed_or_filtered".into(),
        "No TCP connection result".into(),
    )
}

fn normalize_host(input: &str) -> Result<String> {
    let input = input.trim();
    if input.is_empty() || input.len() > 253 || input.chars().any(char::is_whitespace) {
        return Err(ToolError::Operation(
            "remote target is empty or invalid".into(),
        ));
    }
    if input.contains("://") {
        let url = Url::parse(input)
            .map_err(|_| ToolError::Operation("remote target URL is invalid".into()))?;
        return url
            .host_str()
            .map(str::to_string)
            .ok_or_else(|| ToolError::Operation("remote target URL has no host".into()));
    }
    if input.starts_with('[') {
        return input
            .strip_prefix('[')
            .and_then(|value| value.split(']').next())
            .map(str::to_string)
            .ok_or_else(|| ToolError::Operation("remote IPv6 target is invalid".into()));
    }
    if input.parse::<IpAddr>().is_ok() {
        return Ok(input.into());
    }
    Ok(input
        .split(':')
        .next()
        .unwrap_or(input)
        .trim_end_matches('.')
        .to_string())
}

pub fn validate_public_host(host: &str) -> Result<()> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized.ends_with(".local")
        || normalized.ends_with(".internal")
    {
        return Err(ToolError::Operation(
            "remote providers accept only public Internet targets".into(),
        ));
    }
    if let Ok(ip) = normalized.parse::<IpAddr>() {
        let public = match ip {
            IpAddr::V4(ip) => public_ipv4(ip),
            IpAddr::V6(ip) => public_ipv6(ip),
        };
        if !public {
            return Err(ToolError::Operation(
                "private, loopback, link-local, multicast, and unspecified IPs cannot be sent to a remote provider".into(),
            ));
        }
    }
    Ok(())
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || octets[0] == 0
        || octets[0] >= 224
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113))
}

fn public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn display_number(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.1}"))
        .unwrap_or_else(|| "n/a".into())
}

fn limit_raw(value: &str) -> String {
    value.chars().take(MAX_RAW_OUTPUT).collect()
}

fn operation(error: impl std::fmt::Display) -> ToolError {
    ToolError::Operation(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_targets_reject_non_public_addresses() {
        for target in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "localhost",
            "printer.local",
        ] {
            assert!(validate_public_host(target).is_err(), "{target}");
        }
        assert!(validate_public_host("1.1.1.1").is_ok());
        assert!(validate_public_host("example.com").is_ok());
    }

    #[test]
    fn globalping_http_request_preserves_url_parts() {
        let (target, options) = globalping_target_and_options(
            GlobalpingMeasurementKind::Http,
            "https://example.com:8443/health?full=1",
        )
        .unwrap();
        assert_eq!(target, "example.com");
        assert_eq!(options["protocol"], "HTTPS");
        assert_eq!(options["port"], 8443);
        assert_eq!(options["request"]["path"], "/health");
        assert_eq!(options["request"]["query"], "full=1");
    }

    #[test]
    fn remote_limits_are_hard_bounded() {
        assert_eq!(1_u8.clamp(1, MAX_REMOTE_RESULTS as u8), 1);
        assert_eq!(99_u8.clamp(1, MAX_REMOTE_RESULTS as u8), 3);
    }

    #[test]
    fn test_client_can_override_only_provider_origins() {
        let client = RemoteProviderClient::with_endpoints(
            "http://127.0.0.1:9/v1".into(),
            "http://127.0.0.1:9".into(),
        )
        .unwrap();
        assert_eq!(client.globalping_api, "http://127.0.0.1:9/v1");
        assert_eq!(client.check_host_api, "http://127.0.0.1:9");
    }

    #[test]
    #[ignore = "calls the public Globalping service"]
    fn live_globalping_ping_uses_a_real_remote_probe() {
        let result = RemoteProviderClient::new()
            .unwrap()
            .run_globalping(GlobalpingMeasurementRequest {
                kind: GlobalpingMeasurementKind::Ping,
                target: "example.com".into(),
                location: "world".into(),
                limit: 1,
                scope_confirmed: true,
                token: None,
            })
            .unwrap();
        assert!(!result.id.is_empty());
        assert!(!result.nodes.is_empty());
    }

    #[test]
    #[ignore = "calls the public Check-Host service"]
    fn live_remote_tcp_check_uses_a_real_remote_node() {
        let result = RemoteProviderClient::new()
            .unwrap()
            .run_remote_port_check(RemotePortCheckRequest {
                target: "example.com".into(),
                port: 443,
                max_nodes: 1,
                scope_confirmed: true,
            })
            .unwrap();
        assert!(!result.id.is_empty());
        assert!(!result.nodes.is_empty());
    }
}
