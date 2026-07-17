import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import {
  Activity,
  Check,
  ChevronDown,
  CircleDot,
  Database,
  Download,
  Globe2,
  History,
  Languages,
  ListChecks,
  Play,
  RefreshCw,
  Search,
  ShieldCheck,
  Square,
  SquareTerminal,
  Terminal,
  Wrench,
} from "lucide-react";
import {
  defaultPortForProbe,
  extractPort,
  probeAcceptsPort,
  probeRequiresRemoteVantage,
  probeTarget,
  toolNeedsTarget,
} from "./product";
import type {
  Locale,
  ProbeDescriptor,
  ProbeStatus,
  ProbeTargetInput,
  WorkflowDescriptor,
} from "./product";
import {
  defaultScannerProfileFromCatalog,
  scannerField,
  scannerHasField,
  scannerNamespace,
  scannerProfileOptionsFromCatalog,
} from "./interaction";
import type { DesktopScannerProfileId, InteractionCatalog } from "./interaction";
import { HistoryPanel, saveCompletedRun } from "./history";
import type { SavedRun } from "./history";
import {
  boundLiveConsoleLines,
  createLiveEventBuffer,
  type ProbeLiveEvent,
} from "./live-output";
export { boundLiveConsoleLines } from "./live-output";
import dnsxLogo from "./assets/tool-logos/dnsx.png";
import httpxLogo from "./assets/tool-logos/httpx.png";
import naabuLogo from "./assets/tool-logos/naabu.png";
import nexttraceLogo from "./assets/tool-logos/nexttrace.png";
import nmapLogo from "./assets/tool-logos/nmap.png";
import nucleiLogo from "./assets/tool-logos/nuclei.png";
import subfinderLogo from "./assets/tool-logos/subfinder.png";
import trippyLogo from "./assets/tool-logos/trippy.png";
type AppInfo = {
  name: string;
  core_crate: string;
  version: string;
  contract: string;
};

type VerdictStatus = "ok" | "warning" | "failed" | "unknown";

type ResultVerdict = {
  status: VerdictStatus;
  title: string;
  detail?: string | null;
};

type NextAction = {
  id: string;
  label_key: string;
  probe_id: string;
  target: ProbeTargetInput;
};

export type ProbeRunView = {
  descriptor: ProbeDescriptor;
  output: {
    summary?: string;
    summary_rows?: SummaryRow[];
    findings: unknown[];
    warnings?: ProbeWarning[];
    raw?: unknown;
  };
  graph: {
    nodes: Record<string, unknown>;
    edges: unknown[];
  };
  interpretation?: {
    verdict?: ResultVerdict;
    summary?: string | null;
    summary_rows: SummaryRow[];
    next_actions: NextAction[];
  };
};

type ProbeWarning = {
  code?: string;
  message?: string;
};

type EntityValue = {
  type?: string;
  value?: unknown;
};

type CommandPreview = {
  program: string;
  args: string[];
  display: string;
};

type NetworkSummary = {
  egressIp?: string | null;
  dnsServers: string[];
  observedDns: string[];
  error?: string | null;
};

type RemoteVantageProvider = "globalping" | "sonar_nwork_remote_scan";
type RemoteMeasurementKind = "ping" | "traceroute" | "dns" | "mtr" | "http" | "tcp_port";

type RemoteVantageRequest = {
  provider: RemoteVantageProvider;
  measurement: RemoteMeasurementKind;
  target: ProbeTargetInput;
  locations: string[];
  scope_token?: string | null;
};

type RemoteVantagePlan = {
  request: RemoteVantageRequest;
  allowed_probe_ids: string[];
  warning?: string | null;
};

type ToolInstallStrategy =
  | "auto_download"
  | "detect_only"
  | "api_only"
  | "system_installer"
  | "managed_download";
type ToolRisk = "passive" | "safe_remote_vantage" | "active_scanner" | "intrusive_scanner";
type ToolCategory =
  | "path_diagnostics"
  | "dns"
  | "web"
  | "port_discovery"
  | "vuln_scanning"
  | "remote_vantage"
  | "local_inspection";
type ScannerProfileId = DesktopScannerProfileId;

type ScannerPortsId = "top" | "all" | "custom";

type ToolUpdateInfo = {
  source_label: string;
  source_url: string;
  latest_url: string;
  update_supported: boolean;
  update_note: string;
};

type ManagedToolDescriptor = {
  id: string;
  display_name: string;
  source: string | { custom: string };
  install_strategy: ToolInstallStrategy;
  risk: ToolRisk;
  category: ToolCategory;
  capabilities: string[];
  target_kinds: string[];
  interactions: string[];
  scope_requirement: "none" | "active_target" | "intrusive_target";
  default_enabled: boolean;
  notes: string;
  update: ToolUpdateInfo;
};

type ToolUpdatePlan = {
  tool_id: string;
  display_name: string;
  source_label: string;
  source_url: string;
  latest_url: string;
  update_supported: boolean;
  update_note: string;
};

type ToolRuntimeStatus = {
  tool_id: string;
  available: boolean;
  executable?: string | null;
  version?: string | null;
  error?: string | null;
};

type ToolLifecyclePlan = {
  tool_id: string;
  install_strategy: ToolInstallStrategy;
  installed: boolean;
  install_supported: boolean;
  update_supported: boolean;
  managed: boolean;
  action_url?: string | null;
  note: string;
};

type ScannerRunView = {
  summary: ProbeLiveSummary;
  output: {
    summary?: string | null;
    summary_rows: SummaryRow[];
    warnings: ProbeWarning[];
    raw?: unknown;
  };
};

type RemoteNodeResult = {
  location: string;
  network?: string | null;
  status: string;
  summary: string;
  raw_output?: string | null;
};

type GlobalpingMeasurementResult = {
  provider: "globalping";
  id: string;
  measurement: Exclude<RemoteMeasurementKind, "tcp_port">;
  target: string;
  status: string;
  share_url: string;
  nodes: RemoteNodeResult[];
};

type RemotePortCheckResult = {
  provider: "check_host";
  id: string;
  target: string;
  port: number;
  status: string;
  report_url: string;
  nodes: RemoteNodeResult[];
};

type CaptureRuntime = {
  available: boolean;
  tshark?: string | null;
  wireshark?: string | null;
  version?: string | null;
  error?: string | null;
};

type CaptureInterface = { id: string; label: string };
type CaptureResult = {
  path: string;
  bytes: number;
  durationSeconds: number;
  packetLimit: number;
};
type DeviceRecord = {
  ip: string;
  mac?: string | null;
  state: string;
  interface?: string | null;
};
type InventorySnapshot = {
  collectedAt: number;
  source: string;
  devices: DeviceRecord[];
};
type MonitorConfig = {
  id: string;
  target: string;
  intervalSeconds: number;
  latencyAlertMs: number;
  lossAlertPercent: number;
  enabled: boolean;
};
type TimelineEvent = {
  id: string;
  createdAt: number;
  kind: string;
  severity: string;
  title: string;
  detail: string;
  target?: string | null;
  metrics: Record<string, unknown>;
};

type NmapOpenPortView = {
  port: number;
  proto: string;
  service: string;
  detail: string;
};

type NmapHostView = {
  host: string;
  ports: NmapOpenPortView[];
};

type ProbeLiveSummary = {
  command: string;
  exit_code?: number | null;
  stdout: string[];
  stderr: string[];
  truncated: boolean;
  raw_output_path?: string | null;
};

type CommandOutput = {
  command: string;
  args: string[];
  exitCode?: number | null;
  stdout: string;
  stderr: string;
};

type SummaryRow = {
  label: string;
  value: string;
};

type IngressReadinessItem = {
  id: string;
  title: string;
  detail: string;
  status: string;
  tone: "ready" | "waiting" | "planned" | "warning";
  actionLabel?: string;
  actionProbeId?: string;
};

type ThemeMode = "light" | "dark";

const DEFAULT_WORKFLOW_ID = "internet_path";
const DEFAULT_PROBE_ID = "public.egress_check";

const SUGGESTED_TARGETS = new Set(["", "1.1.1.1", "example.com", "example.com:443"]);
const LOCAL_DIRECTION_PROBE_IDS = new Set([
  "public.egress_check",
  "dns.leak_check",
  "dns.lookup",
  "connectivity.ping",
  "connectivity.traceroute",
  "connectivity.fast_trace",
  "connectivity.mtr",
  "connectivity.path_mtu",
  "connectivity.route_check",
  "connectivity.reachability",
  "web.http_probe",
  "web.tls_cert",
]);
const MANAGED_TOOL_WORKFLOWS = [
  { workflowId: "tool_nmap", toolId: "nmap" },
  { workflowId: "tool_nuclei", toolId: "nuclei" },
  { workflowId: "tool_globalping", toolId: "globalping" },
  { workflowId: "tool_httpx", toolId: "httpx" },
  { workflowId: "tool_naabu", toolId: "naabu" },
  { workflowId: "tool_subfinder", toolId: "subfinder" },
  { workflowId: "tool_dnsx", toolId: "dnsx" },
  { workflowId: "tool_trippy", toolId: "trippy" },
  { workflowId: "tool_nexttrace", toolId: "nexttrace" },
  { workflowId: "tool_operations", toolId: "operations" },
] as const;

const PACKAGE_WORKFLOW_IDS = new Set([
  "tool_nmap",
  "tool_nuclei",
  "tool_httpx",
  "tool_naabu",
  "tool_subfinder",
  "tool_dnsx",
  "tool_trippy",
  "tool_nexttrace",
]);

const PACKAGE_GLYPHS: Record<string, string> = {
  tool_nmap: "Nm",
  tool_nuclei: "Nu",
  tool_httpx: "Hx",
  tool_naabu: "Nb",
  tool_subfinder: "Sf",
  tool_dnsx: "Dx",
  tool_trippy: "Tr",
  tool_nexttrace: "Nt",
};

const PACKAGE_LOGOS: Record<string, { src: string; variant: "icon" | "wordmark" }> = {
  tool_nmap: { src: nmapLogo, variant: "icon" },
  tool_nuclei: { src: nucleiLogo, variant: "wordmark" },
  tool_httpx: { src: httpxLogo, variant: "wordmark" },
  tool_naabu: { src: naabuLogo, variant: "wordmark" },
  tool_subfinder: { src: subfinderLogo, variant: "wordmark" },
  tool_dnsx: { src: dnsxLogo, variant: "wordmark" },
  tool_trippy: { src: trippyLogo, variant: "icon" },
  tool_nexttrace: { src: nexttraceLogo, variant: "icon" },
};

export function partitionWorkflowNavigation<T extends Pick<WorkflowDescriptor, "id">>(workflows: T[]) {
  return {
    topWorkflows: workflows.filter((workflow) => !PACKAGE_WORKFLOW_IDS.has(workflow.id)),
    packageWorkflows: workflows.filter((workflow) => PACKAGE_WORKFLOW_IDS.has(workflow.id)),
  };
}

export type PrimaryNavigationView = "diagnose" | "tools" | "operations" | "history";

export function primaryNavigationView(
  workflowId: string | undefined,
  historyOpen: boolean,
): PrimaryNavigationView {
  if (historyOpen) return "history";
  if (workflowId && PACKAGE_WORKFLOW_IDS.has(workflowId)) return "tools";
  if (workflowId === "tool_operations") return "operations";
  return "diagnose";
}

const WORKFLOW_TABS: Record<
  string,
  Record<Locale, { label: string; eyebrow: string; title: string; description: string }>
> = {
  local_network: {
    en: {
      label: "Local host / LAN",
      eyebrow: "Local host",
      title: "Local network state + listening ports",
      description:
        "Interfaces, local IP, gateway, DNS resolvers, listening sockets, and route table.",
    },
    vi: {
      label: "Máy này / LAN",
      eyebrow: "Máy local",
      title: "Trạng thái mạng local + port đang nghe",
      description:
        "Interface, IP local, gateway, DNS resolver, socket đang nghe, và route table.",
    },
  },
  internet_path: {
    en: {
      label: "Local → Internet / target",
      eyebrow: "Local vantage",
      title: "Local checks to Internet / target",
      description:
        "Public IP, DNS, ping, traceroute, HTTP, and TLS all run from the local host.",
    },
    vi: {
      label: "Local → Internet / đích",
      eyebrow: "Góc nhìn local",
      title: "Kiểm tra từ máy local ra Internet / đích",
      description:
        "Public IP, DNS, ping, traceroute, HTTP, TLS đều chạy từ local host.",
    },
  },
  public_service: {
    en: {
      label: "Public service",
      eyebrow: "Public checks",
      title: "Check a public service",
      description: "Ping, port, HTTP, and TLS checks for a public host or service.",
    },
    vi: {
      label: "Dịch vụ public",
      eyebrow: "Kiểm tra public",
      title: "Kiểm tra dịch vụ public",
      description: "Ping, kiểm tra port, HTTP và TLS của máy chủ hoặc dịch vụ public.",
    },
  },
  tool_nmap: {
    en: {
      label: "Nmap",
      eyebrow: "Network mapper",
      title: "Nmap",
      description:
        "Discover open ports and services with a command preview and bounded scan profiles.",
    },
    vi: {
      label: "Nmap",
      eyebrow: "Lập bản đồ mạng",
      title: "Nmap",
      description:
        "Tìm port và dịch vụ đang mở với xem trước lệnh và profile quét có giới hạn.",
    },
  },
  tool_nuclei: {
    en: {
      label: "Nuclei",
      eyebrow: "Template security checks",
      title: "Nuclei",
      description:
        "Run selected security templates against a URL with separate update controls.",
    },
    vi: {
      label: "Nuclei",
      eyebrow: "Kiểm tra bảo mật theo template",
      title: "Nuclei",
      description:
        "Chạy template bảo mật đã chọn trên URL, với cơ chế cập nhật riêng.",
    },
  },
  tool_globalping: {
    en: {
      label: "Globalping",
      eyebrow: "Remote vantage",
      title: "Measure from outside your network",
      description: "Run bounded ping, traceroute, MTR, DNS, or HTTP measurements on real Globalping probes.",
    },
    vi: {
      label: "Globalping",
      eyebrow: "Góc nhìn từ xa",
      title: "Đo từ bên ngoài mạng của bạn",
      description: "Chạy ping, traceroute, MTR, DNS hoặc HTTP có giới hạn trên probe Globalping thật.",
    },
  },
  tool_operations: {
    en: {
      label: "Operations",
      eyebrow: "Local operations",
      title: "Capture, inventory, monitoring and alerts",
      description: "Bounded packet capture, passive device inventory, persistent monitors and an event timeline.",
    },
    vi: {
      label: "Vận hành",
      eyebrow: "Vận hành local",
      title: "Capture, inventory, monitoring và cảnh báo",
      description: "Packet capture có giới hạn, inventory thụ động, monitor lưu bền và timeline sự kiện.",
    },
  },
  tool_httpx: {
    en: {
      label: "httpx",
      eyebrow: "HTTP service probe",
      title: "httpx",
      description: "Check which hosts serve HTTP or HTTPS, including status, page title and detected technologies.",
    },
    vi: {
      label: "httpx",
      eyebrow: "Kiểm tra dịch vụ HTTP",
      title: "httpx",
      description: "Kiểm tra host nào có HTTP/HTTPS, kèm status, tiêu đề trang và công nghệ nhận diện được.",
    },
  },
  tool_naabu: {
    en: {
      label: "naabu",
      eyebrow: "TCP port discovery",
      title: "naabu",
      description: "Find open TCP ports with a bounded connect-mode scan on one target.",
    },
    vi: {
      label: "naabu",
      eyebrow: "Tìm cổng TCP",
      title: "naabu",
      description: "Tìm các cổng TCP đang mở bằng lượt quét connect có giới hạn trên một mục tiêu.",
    },
  },
  tool_subfinder: {
    en: {
      label: "subfinder",
      eyebrow: "Passive subdomain discovery",
      title: "subfinder",
      description: "Collect subdomains from passive public sources without running a port or vulnerability scan.",
    },
    vi: {
      label: "subfinder",
      eyebrow: "Tìm subdomain thụ động",
      title: "subfinder",
      description: "Thu thập subdomain từ các nguồn công khai thụ động, không quét port hay lỗ hổng.",
    },
  },
  tool_dnsx: {
    en: {
      label: "dnsx",
      eyebrow: "DNS resolution",
      title: "dnsx",
      description: "Resolve and validate DNS names and common records with bounded queries.",
    },
    vi: {
      label: "dnsx",
      eyebrow: "Phân giải DNS",
      title: "dnsx",
      description: "Phân giải và xác thực tên DNS cùng các bản ghi phổ biến bằng truy vấn có giới hạn.",
    },
  },
  tool_trippy: {
    en: {
      label: "trippy",
      eyebrow: "Ping + traceroute",
      title: "trippy",
      description: "Combine ping and traceroute to inspect latency and packet loss along the network path.",
    },
    vi: {
      label: "trippy",
      eyebrow: "Ping + traceroute",
      title: "trippy",
      description: "Kết hợp ping và traceroute để xem độ trễ, mất gói trên từng chặng của đường truyền.",
    },
  },
  tool_nexttrace: {
    en: {
      label: "nexttrace",
      eyebrow: "Enriched route trace",
      title: "nexttrace",
      description: "Trace each network hop and enrich the route with ASN and location context.",
    },
    vi: {
      label: "nexttrace",
      eyebrow: "Theo dõi tuyến nâng cao",
      title: "nexttrace",
      description: "Theo dõi từng hop trên đường truyền và bổ sung ngữ cảnh ASN cùng vị trí mạng.",
    },
  },
  public_lookup: {
    en: {
      label: "WHOIS / RDAP",
      eyebrow: "Public lookup",
      title: "WHOIS / RDAP lookup",
      description: "Public registration lookup for a domain, IP, URL, or host:port.",
    },
    vi: {
      label: "WHOIS / RDAP",
      eyebrow: "Tra cứu công khai",
      title: "Tra cứu WHOIS / RDAP",
      description: "Tra cứu đăng ký công khai cho domain, IP, URL hoặc host:port.",
    },
  },
};

const CHECK_COPY: Record<
  string,
  Record<Locale, { eyebrow: string; title: string; subtitle: string }>
> = {
  "local.network_state": {
    en: {
      eyebrow: "Local host",
      title: "Local network state",
      subtitle: "Interfaces, IP, gateway, DNS",
    },
    vi: {
      eyebrow: "Máy local",
      title: "Trạng thái mạng local",
      subtitle: "Giao diện mạng, IP local, gateway, DNS",
    },
  },
  "local.listening_ports": {
    en: {
      eyebrow: "Local listener",
      title: "Listening ports",
      subtitle: "Ports and bind addresses",
    },
    vi: {
      eyebrow: "Cổng lắng nghe local",
      title: "Port đang listen",
      subtitle: "Port và địa chỉ bind",
    },
  },
  "public.egress_check": {
    en: {
      eyebrow: "Local → Internet",
      title: "Public IP + DNS whoami",
      subtitle: "Public IP + DNS whoami",
    },
    vi: {
      eyebrow: "Local → Internet",
      title: "Public IP + DNS whoami",
      subtitle: "IP công khai + DNS whoami",
    },
  },
  "dns.leak_check": {
    en: {
      eyebrow: "Local → DNS",
      title: "DNS leak check",
      subtitle: "Configured vs observed DNS",
    },
    vi: {
      eyebrow: "Local → DNS",
      title: "Kiểm tra DNS leak",
      subtitle: "DNS cấu hình vs DNS quan sát",
    },
  },
  "dns.lookup": {
    en: {
      eyebrow: "Local → DNS",
      title: "DNS lookup / nslookup",
      subtitle: "A/AAAA/MX/TXT/NS records",
    },
    vi: {
      eyebrow: "Local → DNS",
      title: "Tra cứu DNS / nslookup",
      subtitle: "Bản ghi A/AAAA/MX/TXT/NS",
    },
  },
  "connectivity.ping": {
    en: {
      eyebrow: "Local → target",
      title: "Ping",
      subtitle: "Ping + packet loss",
    },
    vi: {
      eyebrow: "Local → đích",
      title: "Ping",
      subtitle: "Ping + tỉ lệ mất gói",
    },
  },
  "connectivity.traceroute": {
    en: {
      eyebrow: "Local → target",
      title: "Traceroute",
      subtitle: "Hop path to target",
    },
    vi: {
      eyebrow: "Local → đích",
      title: "Traceroute",
      subtitle: "Đường đi từng hop tới target",
    },
  },
  "connectivity.fast_trace": {
    en: {
      eyebrow: "Local → target",
      title: "Fast traceroute",
      subtitle: "Short hop-limited trace",
    },
    vi: {
      eyebrow: "Local → đích",
      title: "Traceroute nhanh",
      subtitle: "Trace ngắn theo số hop",
    },
  },
  "connectivity.mtr": {
    en: {
      eyebrow: "Local → target",
      title: "MTR / pathping",
      subtitle: "Latency/loss per hop over several samples",
    },
    vi: {
      eyebrow: "Local → đích",
      title: "MTR / pathping",
      subtitle: "Latency/mất gói theo từng hop qua nhiều mẫu",
    },
  },
  "connectivity.path_mtu": {
    en: {
      eyebrow: "Local → target",
      title: "Path MTU",
      subtitle: "Largest packet size before fragmentation",
    },
    vi: {
      eyebrow: "Local → đích",
      title: "Path MTU",
      subtitle: "Gói lớn nhất trước khi bị fragment",
    },
  },
  "connectivity.route_check": {
    en: {
      eyebrow: "Local route table",
      title: "Route print",
      subtitle: "Route table and selected gateway",
    },
    vi: {
      eyebrow: "Bảng định tuyến local",
      title: "Bảng định tuyến",
      subtitle: "Route table và gateway được chọn",
    },
  },
  "connectivity.reachability": {
    en: {
      eyebrow: "Local reachability",
      title: "TCP connect check",
      subtitle: "Local host to host:port",
    },
    vi: {
      eyebrow: "Kết nối local",
      title: "Kiểm tra kết nối TCP",
      subtitle: "Kết nối local tới host:port",
    },
  },
  "web.http_probe": {
    en: {
      eyebrow: "Local → HTTP",
      title: "HTTP probe",
      subtitle: "HTTP status + headers",
    },
    vi: {
      eyebrow: "Local → HTTP",
      title: "Kiểm tra HTTP",
      subtitle: "Mã trạng thái HTTP + header",
    },
  },
  "web.tls_cert": {
    en: {
      eyebrow: "Local → TLS",
      title: "TLS certificate",
      subtitle: "Handshake + certificate",
    },
    vi: {
      eyebrow: "Local → TLS",
      title: "Chứng chỉ TLS",
      subtitle: "Handshake + chứng chỉ",
    },
  },
  "public.port_check": {
    en: {
      eyebrow: "Public ingress",
      title: "Public port check",
      subtitle: "Requires remote vantage",
    },
    vi: {
      eyebrow: "Dịch vụ public",
      title: "Kiểm tra port public",
      subtitle: "Cần điểm đo bên ngoài",
    },
  },
  "recon.whois_rdap": {
    en: {
      eyebrow: "Public lookup",
      title: "WHOIS / RDAP",
      subtitle: "Registrar, dates, nameservers",
    },
    vi: {
      eyebrow: "Tra cứu công khai",
      title: "WHOIS / RDAP",
      subtitle: "Nhà đăng ký, mốc thời gian, nameserver",
    },
  },
};

const NEXT_ACTION_COPY: Record<string, Record<Locale, string>> = {
  "next_action.check_dns_leak": {
    en: "DNS leak check",
    vi: "Kiểm tra rò rỉ DNS",
  },
  "next_action.trace_path": {
    en: "Traceroute",
    vi: "Traceroute",
  },
  "next_action.check_public_port": {
    en: "Public port check",
    vi: "Kiểm tra cổng public",
  },
};

const SUMMARY_LABELS: Record<string, Record<Locale, string>> = {
  Type: { en: "Type", vi: "Loại" },
  Entity: { en: "Entity", vi: "Thực thể" },
  Target: { en: "Target", vi: "Đích" },
  "Resolved IP": { en: "Resolved IP", vi: "IP đã phân giải" },
  Replies: { en: "Replies", vi: "Gói đã gửi" },
  "Packet loss": { en: "Packet loss", vi: "Mất gói" },
  Latency: { en: "Latency", vi: "Độ trễ TB" },
  Hops: { en: "Hops", vi: "Số chặng" },
  "Last hop": { en: "Last hop", vi: "Chặng cuối" },
  Timeouts: { en: "Timeouts", vi: "Hết thời gian" },
  Route: { en: "Route", vi: "Tuyến" },
  Interface: { en: "Interface", vi: "Giao diện mạng" },
  Gateway: { en: "Gateway", vi: "Gateway" },
  Source: { en: "Source", vi: "Nguồn" },
  "Public IP": { en: "Public IP", vi: "IP công khai" },
  "DNS servers": { en: "DNS servers", vi: "DNS cấu hình" },
  "Observed DNS": { en: "Observed DNS", vi: "DNS quan sát" },
  Errors: { en: "Errors", vi: "Lỗi" },
  "Local IPs": { en: "Local IPs", vi: "IP local" },
  Listeners: { en: "Listeners", vi: "Cổng đang nghe" },
  "Public binds": { en: "Public binds", vi: "Bind mọi interface" },
  Server: { en: "Server", vi: "Máy chủ" },
  Address: { en: "Address", vi: "Địa chỉ" },
  Records: { en: "Records", vi: "Bản ghi" },
  "HTTP status": { en: "HTTP status", vi: "Trạng thái HTTP" },
  "Final URL": { en: "Final URL", vi: "URL cuối" },
  "Content-Type": { en: "Content-Type", vi: "Content-Type" },
  Title: { en: "Title", vi: "Tiêu đề" },
  Security: { en: "Security", vi: "Bảo mật" },
  Protocol: { en: "Protocol", vi: "Giao thức" },
  Subject: { en: "Subject", vi: "Chủ thể" },
  Issuer: { en: "Issuer", vi: "Nhà phát hành" },
  Expires: { en: "Expires", vi: "Hết hạn" },
  Handle: { en: "Handle", vi: "Handle" },
  Country: { en: "Country", vi: "Quốc gia" },
  Nameservers: { en: "Nameservers", vi: "Máy chủ tên" },
  Entities: { en: "Entities", vi: "Thực thể" },
  Connected: { en: "Connected", vi: "Kết nối" },
  Remote: { en: "Remote", vi: "Từ xa" },
  Elapsed: { en: "Elapsed", vi: "Thời gian" },
  Exit: { en: "Exit", vi: "Mã thoát" },
  Lines: { en: "Lines", vi: "Dòng" },
};

type DiagnosticWorkflowPickerProps = {
  active: boolean;
  locale: Locale;
  onSelect: (workflow: WorkflowDescriptor) => void;
  value?: string;
  workflows: WorkflowDescriptor[];
};

function DiagnosticWorkflowPicker({
  active,
  locale,
  onSelect,
  value,
  workflows,
}: DiagnosticWorkflowPickerProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const selectedWorkflow =
    workflows.find((workflow) => workflow.id === value) ?? workflows[0];
  const selectedLabel = selectedWorkflow
    ? workflowCopy(selectedWorkflow.id, locale).label
    : locale === "vi"
      ? "Chọn góc chẩn đoán"
      : "Choose diagnostic view";
  const pickerLabel = locale === "vi" ? "Chọn góc chẩn đoán" : "Choose diagnostic view";

  useEffect(() => {
    if (!open) return;
    const selectedOption = rootRef.current?.querySelector<HTMLButtonElement>(
      '.primaryNavOption[aria-selected="true"]',
    );
    selectedOption?.focus();
  }, [open]);

  function closeAndRestoreFocus() {
    setOpen(false);
    triggerRef.current?.focus();
  }

  function handleOptionKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>) {
    const options = Array.from(
      rootRef.current?.querySelectorAll<HTMLButtonElement>(".primaryNavOption") ?? [],
    );
    const currentIndex = options.indexOf(event.currentTarget);
    let nextIndex = currentIndex;

    if (event.key === "ArrowDown") nextIndex = (currentIndex + 1) % options.length;
    else if (event.key === "ArrowUp") nextIndex = (currentIndex - 1 + options.length) % options.length;
    else if (event.key === "Home") nextIndex = 0;
    else if (event.key === "End") nextIndex = options.length - 1;
    else if (event.key === "Escape") {
      event.preventDefault();
      closeAndRestoreFocus();
      return;
    } else return;

    event.preventDefault();
    options[nextIndex]?.focus();
  }

  return (
    <div
      ref={rootRef}
      aria-current={active ? "page" : undefined}
      className={`primaryNavSelect ${active ? "active" : ""}`}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false);
      }}
    >
      <span className="primaryNavLabel" id="diagnostic-workflow-label">
        <ListChecks size={15} />
        {locale === "vi" ? "Chẩn đoán" : "Diagnose"}
      </span>
      <div className="primaryNavSelectControl">
        <button
          ref={triggerRef}
          type="button"
          className="primaryNavSelectTrigger"
          aria-controls="diagnostic-workflow-menu"
          aria-expanded={open}
          aria-haspopup="listbox"
          aria-label={`${pickerLabel}: ${selectedLabel}`}
          onClick={() => setOpen((current) => !current)}
          onKeyDown={(event) => {
            if (event.key === "ArrowDown" || event.key === "ArrowUp") {
              event.preventDefault();
              setOpen(true);
            } else if (event.key === "Escape" && open) {
              event.preventDefault();
              setOpen(false);
            }
          }}
        >
          <span>{selectedLabel}</span>
          <ChevronDown className={open ? "open" : ""} size={15} />
        </button>
        {open ? (
          <div
            className="primaryNavMenu"
            id="diagnostic-workflow-menu"
            role="listbox"
            aria-labelledby="diagnostic-workflow-label"
          >
            {workflows.map((workflow) => {
              const selected = workflow.id === selectedWorkflow?.id;
              return (
                <button
                  type="button"
                  className="primaryNavOption"
                  data-workflow-id={workflow.id}
                  key={workflow.id}
                  role="option"
                  aria-selected={selected}
                  onClick={() => {
                    onSelect(workflow);
                    closeAndRestoreFocus();
                  }}
                  onKeyDown={handleOptionKeyDown}
                >
                  <Check size={14} />
                  <span>{workflowCopy(workflow.id, locale).label}</span>
                </button>
              );
            })}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export default function App() {
  const [locale, setLocale] = useState<Locale>(getInitialLocale);
  const [theme, setTheme] = useState<ThemeMode>(getInitialTheme);
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [target, setTarget] = useState("1.1.1.1");
  const [entity, setEntity] = useState<EntityValue | null>(null);
  const [catalog, setCatalog] = useState<ProbeDescriptor[]>([]);
  const [workflows, setWorkflows] = useState<WorkflowDescriptor[]>([]);
  const [managedTools, setManagedTools] = useState<ManagedToolDescriptor[]>([]);
  const [interactionCatalog, setInteractionCatalog] = useState<InteractionCatalog | null>(null);
  const [availableProbes, setAvailableProbes] = useState<ProbeDescriptor[]>([]);
  const [networkSummary, setNetworkSummary] = useState<NetworkSummary | null>(null);
  const [remotePlan, setRemotePlan] = useState<RemoteVantagePlan | null>(null);
  const [remotePlanError, setRemotePlanError] = useState<string | null>(null);
  const [activeWorkflowId, setActiveWorkflowId] = useState(DEFAULT_WORKFLOW_ID);
  const [selectedProbeId, setSelectedProbeId] = useState(DEFAULT_PROBE_ID);
  const [result, setResult] = useState<ProbeRunView | null>(null);
  const [historyRevision, setHistoryRevision] = useState(0);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [commandPreview, setCommandPreview] = useState<CommandPreview | null>(null);
  const [commandText, setCommandText] = useState("");
  const [commandDirty, setCommandDirty] = useState(false);
  const [targetPort, setTargetPort] = useState("");
  const [liveLines, setLiveLines] = useState<string[]>([]);
  const [liveExitCode, setLiveExitCode] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  const [isNetworkSummaryLoading, setIsNetworkSummaryLoading] = useState(false);
  const [isRemotePlanLoading, setIsRemotePlanLoading] = useState(false);
  const [isLiveRunning, setIsLiveRunning] = useState(false);
  const [isStoppingLive, setIsStoppingLive] = useState(false);
  const [liveWasStopped, setLiveWasStopped] = useState(false);
  const liveRunIdRef = useRef<string | null>(null);
  const liveStoppedRef = useRef(false);
  const liveConsoleRef = useRef<HTMLPreElement | null>(null);
  const lastPackageWorkflowIdRef = useRef<string | null>(null);

  const workflowList = useMemo(
    () => uiWorkflows(workflows.length > 0 ? workflows : fallbackWorkflows(), catalog),
    [catalog, workflows],
  );
  const { topWorkflows, packageWorkflows } = useMemo(
    () => partitionWorkflowNavigation(workflowList),
    [workflowList],
  );
  const activeWorkflow =
    workflowList.find((workflow) => workflow.id === activeWorkflowId) ?? workflowList[0];
  const activeWorkflowCopy = workflowCopy(activeWorkflow?.id, locale);
  const activeToolId = toolIdForWorkflow(activeWorkflow?.id);
  const diagnosticWorkflows = useMemo(
    () => topWorkflows.filter((workflow) => workflow.id !== "tool_operations"),
    [topWorkflows],
  );
  const operationsWorkflow = topWorkflows.find(
    (workflow) => workflow.id === "tool_operations",
  );
  const showPackageSidebar = Boolean(
    activeWorkflow?.id && PACKAGE_WORKFLOW_IDS.has(activeWorkflow.id),
  );
  const activePrimaryView = primaryNavigationView(activeWorkflow?.id, historyOpen);
  const diagnosticWorkflowValue = diagnosticWorkflows.some(
    (workflow) => workflow.id === activeWorkflow?.id,
  )
    ? activeWorkflow?.id
    : diagnosticWorkflows[0]?.id;
  const activeManagedTool = useMemo(
    () => (activeToolId ? managedToolForId(managedTools, activeToolId) : undefined),
    [activeToolId, managedTools],
  );

  const workflowTools = useMemo(
    () =>
      probesByIds(catalog, [
        ...(activeWorkflow?.primary_probe_ids ?? []),
        ...(activeWorkflow?.advanced_probe_ids ?? []),
      ]),
    [activeWorkflow, catalog],
  );
  const workflowProbeIds = useMemo(
    () =>
      new Set([
        ...(activeWorkflow?.primary_probe_ids ?? []),
        ...(activeWorkflow?.advanced_probe_ids ?? []),
      ]),
    [activeWorkflow],
  );
  const availableIds = useMemo(
    () => new Set(availableProbes.map((probe) => probe.id)),
    [availableProbes],
  );

  const selectedProbe = useMemo<ProbeDescriptor | undefined>(() => {
    if (activeToolId) {
      return undefined;
    }

    const inWorkflow = catalog.find(
      (probe) => probe.id === selectedProbeId && workflowProbeIds.has(probe.id),
    );
    return (
      inWorkflow ??
      workflowTools[0] ??
      catalog.find((probe) => probe.id === selectedProbeId) ??
      catalog[0]
    );
  }, [activeToolId, catalog, selectedProbeId, workflowProbeIds, workflowTools]);

  const selectedCopy = selectedProbe
    ? checkCopy(selectedProbe, locale, activeWorkflow?.id)
    : null;
  const selectedNeedsTarget = selectedProbe ? toolNeedsTarget(selectedProbe) : true;
  const selectedAcceptsPort = selectedProbe ? probeAcceptsPort(selectedProbe.id) : false;
  const selectedRequiresRemote = selectedProbe
    ? probeRequiresRemoteVantage(selectedProbe.id)
    : false;
  const selectedApplies = Boolean(
    selectedProbe && entity && availableIds.has(selectedProbe.id),
  );
  const hasTarget = target.trim().length > 0;
  const hasToolInput = !selectedNeedsTarget || hasTarget;
  const selectedRunnable = Boolean(
    selectedProbe &&
      hasToolInput &&
      selectedProbe.status === "ready" &&
      !selectedRequiresRemote &&
      (!selectedNeedsTarget || !entity || selectedApplies),
  );
  const cleanCommandText = commandText.trim();
  const commandOverride =
    commandPreview &&
    commandDirty &&
    cleanCommandText.length > 0 &&
    cleanCommandText !== commandPreview.display.trim()
      ? cleanCommandText
      : null;
  const usesCustomCommand = Boolean(commandOverride);
  const egressLabel =
    networkSummary?.egressIp ??
    (isNetworkSummaryLoading
      ? locale === "vi"
        ? "đang kiểm tra"
        : "checking"
      : locale === "vi"
        ? "chưa rõ"
        : "unknown");
  const dnsTitle = formatDnsTitle(networkSummary, locale);
  const resultRows = resultSummaryRows(result, locale);
  const verdict = resultVerdict(
    result,
    liveLines,
    liveExitCode,
    isLiveRunning,
    liveWasStopped,
    selectedProbe,
    locale,
  );
  const rawOutput = formatOutputDetail({
    result,
    liveLines,
    selectedProbe,
    commandPreview,
    locale,
  });
  const liveOutputText = normalizeTerminalText(liveLines.join("\n"));
  const liveLineCount = liveOutputText
    ? liveOutputText.split("\n").filter((line) => line.trim().length > 0).length
    : 0;

  useEffect(() => {
    window.localStorage.setItem("sonarnwork.locale", locale);
  }, [locale]);

  useEffect(() => {
    window.localStorage.setItem("sonarnwork.theme", theme);
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  useEffect(() => {
    const consoleEl = liveConsoleRef.current;
    if (!consoleEl) {
      return;
    }

    consoleEl.scrollTop = consoleEl.scrollHeight;
  }, [liveLines, isLiveRunning]);

  useEffect(() => {
    async function boot() {
      try {
        const [nextInfo, nextCatalog, nextWorkflows, nextTools, nextInteractions] = await Promise.all([
          invoke<AppInfo>("app_info"),
          invoke<ProbeDescriptor[]>("all_probes"),
          invoke<WorkflowDescriptor[]>("workflows"),
          invoke<{ tools: ManagedToolDescriptor[] }>("tools_catalog"),
          invoke<InteractionCatalog>("interaction_catalog"),
        ]);
        setInfo(nextInfo);
        setCatalog(nextCatalog);
        setWorkflows(nextWorkflows);
        setManagedTools(nextTools.tools);
        setInteractionCatalog(nextInteractions);
        applyInitialSelection(nextWorkflows, nextCatalog);
      } catch (err) {
        if (isTauriRuntimeUnavailable(err)) {
          const nextCatalog = fallbackCatalog();
          const nextWorkflows = fallbackWorkflows();
          setInfo(fallbackAppInfo());
          setCatalog(nextCatalog);
          setWorkflows(nextWorkflows);
          setManagedTools(fallbackManagedTools());
          setInteractionCatalog(null);
          applyInitialSelection(nextWorkflows, nextCatalog);
          setError(null);
          return;
        }

        setError(String(err));
      }
    }

    void boot();
    void refreshNetworkSummary();
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    const liveEvents = createLiveEventBuffer({
      appendLines: (nextLines) =>
        setLiveLines((lines) => boundLiveConsoleLines([...lines, ...nextLines])),
      onStart: (command) =>
        setLiveLines((lines) =>
          lines.length > 0 ? lines : [`$ ${compactCommandDisplay(command)}`],
        ),
      onExit: setLiveExitCode,
    });

    async function bindLiveOutput() {
      if (!hasTauriRuntime()) {
        return;
      }

      unlisten = await listen<ProbeLiveEvent>("probe-live-output", (event) => {
        const payload = event.payload;
        if (payload.run_id !== liveRunIdRef.current) {
          return;
        }
        liveEvents.handle(payload);
      });

      if (disposed && unlisten) {
        unlisten();
      }
    }

    void bindLiveOutput();

    return () => {
      disposed = true;
      liveEvents.dispose();
      if (unlisten) {
        unlisten();
      }
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadCommandPreview() {
      if (
        !selectedProbe ||
        selectedProbe.status !== "ready" ||
        !hasToolInput ||
        probeRequiresRemoteVantage(selectedProbe.id)
      ) {
        setCommandPreview(null);
        setCommandText("");
        setCommandDirty(false);
        return;
      }

      try {
        const preview = await invoke<CommandPreview>("probe_command", {
          probeId: selectedProbe.id,
          target: probeTarget(selectedProbe, target, targetPort),
        });
        if (!cancelled) {
          setCommandPreview(preview);
          setCommandText(preview.display);
          setCommandDirty(false);
        }
      } catch {
        if (!cancelled) {
          setCommandPreview(null);
          setCommandText("");
          setCommandDirty(false);
        }
      }
    }

    void loadCommandPreview();

    return () => {
      cancelled = true;
    };
  }, [hasToolInput, selectedProbe, target, targetPort]);

  useEffect(() => {
    let cancelled = false;

    if (!selectedProbe || !selectedRequiresRemote || !hasToolInput) {
      setRemotePlan(null);
      setRemotePlanError(null);
      setIsRemotePlanLoading(false);
      return;
    }

    const requestTarget = probeTarget(selectedProbe, target, targetPort);

    async function loadRemotePlan() {
      setIsRemotePlanLoading(true);
      setRemotePlanError(null);
      try {
        const plan = await invoke<RemoteVantagePlan>("remote_vantage_plan", {
          provider: "sonar_nwork_remote_scan",
          measurement: "tcp_port",
          target: requestTarget,
        });
        if (!cancelled) {
          setRemotePlan(plan);
        }
      } catch (err) {
        if (!cancelled) {
          if (isTauriRuntimeUnavailable(err)) {
            setRemotePlan(fallbackRemotePlan(requestTarget));
            setRemotePlanError(null);
          } else {
            setRemotePlan(null);
            setRemotePlanError(String(err));
          }
        }
      } finally {
        if (!cancelled) {
          setIsRemotePlanLoading(false);
        }
      }
    }

    void loadRemotePlan();

    return () => {
      cancelled = true;
    };
  }, [hasToolInput, selectedProbe, selectedRequiresRemote, target, targetPort]);

  useEffect(() => {
    if (!selectedProbe || !probeAcceptsPort(selectedProbe.id)) {
      setTargetPort("");
      return;
    }

    setTargetPort(
      (current) => current || extractPort(target) || defaultPortForProbe(selectedProbe.id),
    );
  }, [selectedProbe, target]);

  function applyInitialSelection(nextWorkflows: WorkflowDescriptor[], nextCatalog: ProbeDescriptor[]) {
    const nextUiWorkflows = uiWorkflows(nextWorkflows, nextCatalog);
    const workflow =
      nextUiWorkflows.find((item) => item.id === DEFAULT_WORKFLOW_ID) ?? nextUiWorkflows[0];
    const probeId = preferredProbeId(workflow, nextCatalog);

    if (workflow) {
      setActiveWorkflowId(workflow.id);
      setTarget(defaultTargetForWorkflow(workflow.id));
    }
    if (probeId) {
      setSelectedProbeId(probeId);
    }
  }

  async function refreshNetworkSummary() {
    setIsNetworkSummaryLoading(true);
    try {
      const summary = await invoke<NetworkSummary>("network_summary");
      setNetworkSummary(summary);
    } catch (err) {
      setNetworkSummary({
        egressIp: null,
        dnsServers: [],
        observedDns: [],
        error: isTauriRuntimeUnavailable(err) ? null : String(err),
      });
    } finally {
      setIsNetworkSummaryLoading(false);
    }
  }

  function selectWorkflow(workflow: WorkflowDescriptor) {
    setHistoryOpen(false);
    if (PACKAGE_WORKFLOW_IDS.has(workflow.id)) {
      lastPackageWorkflowIdRef.current = workflow.id;
    }
    setActiveWorkflowId(workflow.id);
    if (toolIdForWorkflow(workflow.id)) {
      setEntity(null);
      setAvailableProbes([]);
      setResult(null);
      setRemotePlan(null);
      setRemotePlanError(null);
      setIsRemotePlanLoading(false);
      setLiveLines([]);
      setIsStoppingLive(false);
      setLiveWasStopped(false);
      liveStoppedRef.current = false;
      setCommandText("");
      setCommandDirty(false);
      setCommandPreview(null);
      setError(null);
      return;
    }

    setSelectedProbeId(preferredProbeId(workflow, catalog) ?? selectedProbeId);
    setTarget((current) =>
      SUGGESTED_TARGETS.has(current.trim()) ? defaultTargetForWorkflow(workflow.id) : current,
    );
    setEntity(null);
    setAvailableProbes([]);
    setResult(null);
    setLiveLines([]);
    setIsStoppingLive(false);
    setLiveWasStopped(false);
    liveStoppedRef.current = false;
    setCommandText("");
    setCommandDirty(false);
    setError(null);
  }

  function selectProbe(probe: ProbeDescriptor) {
    setSelectedProbeId(probe.id);
    setResult(null);
    setLiveLines([]);
    setIsStoppingLive(false);
    setLiveWasStopped(false);
    liveStoppedRef.current = false;
    setCommandText("");
    setCommandDirty(false);
    setError(null);
  }

  function selectProbeId(probeId: string) {
    const probe = catalog.find((item) => item.id === probeId);
    if (probe) {
      selectProbe(probe);
    }
  }

  function handleTargetChange(value: string) {
    setTarget(value);
    const nextPort = extractPort(value);
    if (nextPort) {
      setTargetPort(nextPort);
    }
    setEntity(null);
    setAvailableProbes([]);
    setResult(null);
    setLiveLines([]);
    setIsStoppingLive(false);
    setLiveWasStopped(false);
    liveStoppedRef.current = false;
    setError(null);
  }

  async function inspectTarget(
    nextTarget = target,
    nextCatalog = catalog,
  ): Promise<ProbeDescriptor[] | null> {
    const cleanTarget = nextTarget.trim();
    setError(null);
    setResult(null);
    if (!cleanTarget) {
      setEntity(null);
      setAvailableProbes([]);
      return null;
    }

    setIsBusy(true);
    try {
      const parsed = await invoke<EntityValue>("parse_entity", { input: cleanTarget });
      const nextProbes = await invoke<ProbeDescriptor[]>("available_probes", {
        input: cleanTarget,
      });
      setEntity(parsed);
      setAvailableProbes(nextProbes);

      const selectedStillExists = nextCatalog.some((probe) => probe.id === selectedProbeId);
      if (!selectedStillExists && nextCatalog.length > 0) {
        setSelectedProbeId(nextCatalog[0].id);
      }
      return nextProbes;
    } catch (err) {
      setEntity(null);
      setAvailableProbes([]);
      setError(String(err));
      return null;
    } finally {
      setIsBusy(false);
    }
  }

  async function ensureProbeTarget() {
    if (!selectedProbe || !hasToolInput) {
      return false;
    }

    if (!selectedNeedsTarget) {
      setEntity(null);
      setAvailableProbes([]);
      return true;
    }

    const nextProbes = await inspectTarget();
    if (!nextProbes) {
      return false;
    }

    if (!nextProbes.some((probe) => probe.id === selectedProbe.id)) {
      setError(
        locale === "vi"
          ? "Kiểm tra này không áp dụng cho đích vừa nhập."
          : "This check does not apply to the entered target.",
      );
      return false;
    }

    return true;
  }

  async function runSelectedProbe() {
    if (!selectedProbe || !selectedRunnable) {
      return;
    }

    const canRun = await ensureProbeTarget();
    if (!canRun) {
      return;
    }

    setError(null);
    setLiveLines([]);
    setLiveWasStopped(false);
    liveStoppedRef.current = false;
    setIsBusy(true);
    try {
      const resolvedTarget = probeTarget(selectedProbe, target, targetPort);
      const response = await invoke<ProbeRunView>("run_probe", {
        probeId: selectedProbe.id,
        target: resolvedTarget,
      });
      setResult(response);
      try {
        await saveCompletedRun(response, formatProbeTarget(resolvedTarget));
        setHistoryRevision((revision) => revision + 1);
      } catch (historyError) {
        setError(
          locale === "vi"
            ? `Kết quả đã chạy nhưng chưa lưu được: ${String(historyError)}`
            : `The probe completed but could not be saved: ${String(historyError)}`,
        );
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setIsBusy(false);
    }
  }

  async function runPrimaryAction() {
    if (usesCustomCommand) {
      await runLiveProbe();
      return;
    }

    await runSelectedProbe();
  }

  async function runLiveProbe() {
    if (!selectedProbe || !selectedRunnable || !commandPreview || isLiveRunning) {
      return;
    }

    const canRun = await ensureProbeTarget();
    if (!canRun) {
      return;
    }

    const runId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    liveRunIdRef.current = runId;
    liveStoppedRef.current = false;
    setResult(null);
    setLiveExitCode(null);
    setLiveLines([`$ ${commandOverride ?? commandPreviewLabel(selectedProbe, commandPreview)}`]);
    setError(null);
    setIsLiveRunning(true);
    setIsStoppingLive(false);
    setLiveWasStopped(false);

    try {
      const summary = await invoke<ProbeLiveSummary>("run_probe_live", {
        runId,
        probeId: selectedProbe.id,
        target: probeTarget(selectedProbe, target, targetPort),
        commandOverride,
      });
      const wasStopped = liveStoppedRef.current;
      const exitLine = `[exit] code ${summary.exit_code ?? "unknown"}`;
      setLiveExitCode(summary.exit_code ?? null);
      setLiveLines((lines) =>
        boundLiveConsoleLines([
          ...lines,
          ...(hasStreamedLivePayload(lines) ? [] : capturedLiveLines(summary)),
          ...(hasStreamedLivePayload(lines) ? [exitLine] : []),
          ...(hasStreamedLivePayload(lines) && summary.truncated && summary.raw_output_path
            ? [`[output truncated; full log: ${summary.raw_output_path}]`]
            : []),
          wasStopped
            ? `\n[stopped] ${summary.command} stopped with ${summary.exit_code ?? "unknown"}; partial output kept`
            : `\n[done] ${summary.command} exited with ${summary.exit_code ?? "unknown"}`,
        ]),
      );
    } catch (err) {
      setError(String(err));
      setLiveExitCode(-1);
      setLiveLines((lines) => boundLiveConsoleLines([...lines, `\n[exit] code -1`]));
    } finally {
      setIsLiveRunning(false);
      setIsStoppingLive(false);
      liveRunIdRef.current = null;
    }
  }

  async function stopLiveProbe() {
    const runId = liveRunIdRef.current;
    if (!runId || isStoppingLive) {
      return;
    }

    setIsStoppingLive(true);
    try {
      const stopped = await invoke<boolean>("cancel_probe_live", { runId });
      if (stopped) {
        liveStoppedRef.current = true;
        setLiveWasStopped(true);
      }
      setLiveLines((lines) => [
        ...lines,
        stopped
          ? locale === "vi"
            ? "\n[stop] đã gửi lệnh dừng"
            : "\n[stop] stop requested"
          : locale === "vi"
            ? "\n[stop] không tìm thấy tiến trình đang chạy"
            : "\n[stop] no running process found",
      ]);
      if (!stopped) {
        setIsStoppingLive(false);
      }
    } catch (err) {
      setError(String(err));
      setIsStoppingLive(false);
    }
  }

  async function openTerminalForProbe() {
    if (!selectedProbe || !selectedRunnable || !commandPreview) {
      return;
    }

    const canRun = await ensureProbeTarget();
    if (!canRun) {
      return;
    }

    try {
      await invoke("open_probe_terminal", {
        probeId: selectedProbe.id,
        target: probeTarget(selectedProbe, target, targetPort),
        commandOverride,
      });
    } catch (err) {
      setError(String(err));
    }
  }

  function applyNextAction(action: NextAction) {
    const probe = catalog.find((item) => item.id === action.probe_id);
    if (!probe) {
      return;
    }

    setSelectedProbeId(probe.id);
    if (action.target?.type === "input" && action.target.value.trim().length > 0) {
      setTarget(action.target.value);
    }
    setResult(null);
    setLiveLines([]);
    setError(null);
  }

  function openSavedRun(saved: SavedRun) {
    const matchingWorkflow = workflowList.find(
      (workflow) =>
        workflow.primary_probe_ids.includes(saved.probe_id) ||
        workflow.advanced_probe_ids.includes(saved.probe_id),
    );
    if (matchingWorkflow) selectWorkflow(matchingWorkflow);
    handleTargetChange(saved.target);
    setSelectedProbeId(saved.probe_id);
    setResult(saved.result as ProbeRunView);
  }

  function openTools() {
    const workflow =
      packageWorkflows.find(
        (candidate) => candidate.id === lastPackageWorkflowIdRef.current,
      ) ?? packageWorkflows[0];
    if (workflow) selectWorkflow(workflow);
  }

  function openHistory() {
    setHistoryOpen(true);
    setError(null);
  }

  return (
    <main
      className="shell"
      data-theme={theme}
      data-workflow={activeWorkflow?.id ?? DEFAULT_WORKFLOW_ID}
    >
      <section className="appWindow">
        <header className="appTopbar">
          <div className="brandMark">
            <span className="brandIcon" aria-hidden="true">
              <span className="brandNode" />
              <span className="brandWave brandWaveOne" />
              <span className="brandWave brandWaveTwo" />
            </span>
            <strong>{info?.name ?? "SonarNwork"}</strong>
          </div>

          <nav
            className="primaryNav"
            aria-label={locale === "vi" ? "Điều hướng chính" : "Primary navigation"}
          >
            <DiagnosticWorkflowPicker
              active={activePrimaryView === "diagnose"}
              locale={locale}
              onSelect={selectWorkflow}
              value={diagnosticWorkflowValue}
              workflows={diagnosticWorkflows}
            />
            <button
              type="button"
              data-primary-view="tools"
              aria-current={activePrimaryView === "tools" ? "page" : undefined}
              className={`primaryNavButton ${activePrimaryView === "tools" ? "active" : ""}`}
              disabled={packageWorkflows.length === 0}
              onClick={openTools}
            >
              <Wrench size={15} />
              <span>{locale === "vi" ? "Công cụ" : "Tools"}</span>
            </button>
            <button
              type="button"
              data-primary-view="operations"
              aria-current={activePrimaryView === "operations" ? "page" : undefined}
              className={`primaryNavButton ${activePrimaryView === "operations" ? "active" : ""}`}
              disabled={!operationsWorkflow}
              onClick={() => operationsWorkflow && selectWorkflow(operationsWorkflow)}
            >
              <Activity size={15} />
              <span>{locale === "vi" ? "Vận hành" : "Operations"}</span>
            </button>
            <button
              type="button"
              data-primary-view="history"
              aria-current={activePrimaryView === "history" ? "page" : undefined}
              className={`primaryNavButton ${activePrimaryView === "history" ? "active" : ""}`}
              onClick={openHistory}
            >
              <History size={15} />
              <span>{locale === "vi" ? "Lịch sử" : "History"}</span>
            </button>
          </nav>

          <div className="topTools">
            <button
              className="iconTextButton"
              onClick={() => setLocale(locale === "vi" ? "en" : "vi")}
              title={locale === "vi" ? "Switch to English" : "Đổi sang tiếng Việt"}
            >
              <Languages size={14} />
              <span>{locale.toUpperCase()}</span>
            </button>
            <button
              className="iconTextButton"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            >
              <CircleDot size={13} />
              <span>{theme === "dark" ? (locale === "vi" ? "Tối" : "Dark") : locale === "vi" ? "Sáng" : "Light"}</span>
            </button>
          </div>
        </header>

        <section className={`appBody ${showPackageSidebar ? "hasPackageSidebar" : ""}`}>
          {showPackageSidebar ? (
            <aside
            className="packageSidebar"
            aria-label={locale === "vi" ? "Các gói công cụ" : "Tool packages"}
          >
            <header className="packageSidebarHeader">
              <span className="packageSidebarIcon" aria-hidden="true">
                <Download size={15} />
              </span>
              <span className="packageSidebarTitle">
                <strong>{locale === "vi" ? "Gói công cụ" : "Packages"}</strong>
                <small>{locale === "vi" ? "Cài thêm khi cần" : "Install when needed"}</small>
              </span>
              <span className="packageCount">{packageWorkflows.length}</span>
            </header>

            <nav className="packageNav">
                {packageWorkflows.map((workflow) => {
                  const copy = workflowCopy(workflow.id, locale);
                  const active = workflow.id === activeWorkflow?.id;
                  const logo = PACKAGE_LOGOS[workflow.id];
                  return (
                  <button
                    aria-current={active ? "page" : undefined}
                    className={active ? "active" : ""}
                    data-workflow-id={workflow.id}
                    key={workflow.id}
                    onClick={() => selectWorkflow(workflow)}
                    title={`${copy.title} — ${copy.description}`}
                  >
                    <span className="packageGlyph" data-package-id={workflow.id} aria-hidden="true">
                      {logo ? (
                        <>
                          <img
                            alt=""
                            className={`packageLogo packageLogo--${logo.variant}`}
                            src={logo.src}
                            onError={(event) => {
                              event.currentTarget.hidden = true;
                              const fallback = event.currentTarget.nextElementSibling;
                              if (fallback instanceof HTMLElement) {
                                fallback.hidden = false;
                              }
                            }}
                          />
                          <span className="packageLogoFallback" hidden>
                            {PACKAGE_GLYPHS[workflow.id] ?? "•"}
                          </span>
                        </>
                      ) : (
                        PACKAGE_GLYPHS[workflow.id] ?? "•"
                      )}
                    </span>
                    <span className="packageNavText">
                      <strong>{copy.label}</strong>
                      <small>{copy.eyebrow}</small>
                    </span>
                  </button>
                );
              })}
            </nav>

            <p className="packageSidebarHint">
              {locale === "vi"
                ? "Các CLI tùy chọn. App sẽ dò runtime trước khi chạy."
                : "Optional CLIs. The app detects each runtime before running it."}
            </p>
            </aside>
          ) : null}

          <section className="workspace">
          <header className="questionHeader">
            <p>
              {historyOpen
                ? locale === "vi"
                  ? "Hồ sơ chẩn đoán"
                  : "Diagnostic record"
                : activeWorkflowCopy.eyebrow}
            </p>
            <h1>
              {historyOpen
                ? locale === "vi"
                  ? "Lịch sử và so sánh kết quả"
                  : "History and result comparison"
                : activeWorkflowCopy.title}
            </h1>
            <span>
              {historyOpen
                ? locale === "vi"
                  ? "Tìm lại lần chạy đã lưu, mở chi tiết hoặc so sánh hai kết quả."
                  : "Find saved runs, reopen their details, or compare two results."
                : activeWorkflowCopy.description}
            </span>
          </header>

          {historyOpen ? (
            <HistoryPanel
              locale={locale}
              refreshToken={historyRevision}
              onOpenRun={openSavedRun}
              onStorageError={(message) => setError(message)}
            />
          ) : activeToolId ? (
            activeToolId === "globalping" ? (
              <RemoteMeasurementPage locale={locale} />
            ) : activeToolId === "operations" ? (
              <OperationsPage locale={locale} />
            ) : (
              <ManagedToolPage
                locale={locale}
                tool={activeManagedTool}
                toolId={activeToolId}
                interactionCatalog={interactionCatalog}
              />
            )
          ) : (
            <div className="diagnosticWorkbench">
              <aside
                className="checkRail"
                aria-label={locale === "vi" ? "Bộ kiểm tra" : "Check picker"}
              >
                <div className="checkRailHeader">
                  <div>
                    <small>{locale === "vi" ? "Bộ kiểm tra" : "Check set"}</small>
                    <strong>{locale === "vi" ? "Chọn phép đo" : "Choose a measurement"}</strong>
                  </div>
                  <span>{workflowTools.length}</span>
                </div>
                <label className="compactCheckPicker">
                  <span>{locale === "vi" ? "Kiểm tra đang chọn" : "Selected check"}</span>
                  <select
                    name="diagnostic-check"
                    value={selectedProbe?.id ?? ""}
                    onChange={(event) => selectProbeId(event.target.value)}
                  >
                    {workflowTools.map((probe) => (
                      <option key={probe.id} value={probe.id}>
                        {checkCopy(probe, locale, activeWorkflow?.id).title}
                      </option>
                    ))}
                  </select>
                </label>
                <section
                  className="checkGrid"
                  aria-label={locale === "vi" ? "Kiểm tra đề xuất" : "Recommended checks"}
                >
                  {workflowTools.map((probe) => (
                    <CheckCard
                      key={probe.id}
                      probe={probe}
                      locale={locale}
                      active={probe.id === selectedProbe?.id}
                      workflowId={activeWorkflow?.id}
                      disabled={probe.status === "planned"}
                      onSelect={() => selectProbe(probe)}
                    />
                  ))}
                </section>
              </aside>

              <div className="diagnosticStage">
          {error ? <p className="errorBanner" role="alert">{error}</p> : null}

          {selectedProbe ? (
            <section className={`runPanel direction-${directionClass(selectedProbe.id)}`}>
              <div className="runLabel">
                <span>→</span>
                <strong>{selectedCopy?.title ?? selectedProbe.name}</strong>
                <em>{directionLabel(selectedProbe.id, locale)}</em>
              </div>

              <div className={selectedNeedsTarget ? "runControls" : "runControls targetless"}>
                {selectedNeedsTarget ? (
                  <label className="targetInput">
                    <Search size={15} />
                    <input
                      name="diagnostic-target"
                      value={target}
                      placeholder={
                        activeWorkflow?.id === "public_service"
                          ? "example.com:443"
                          : activeWorkflow?.id === "public_lookup"
                            ? "example.com"
                            : "1.1.1.1"
                      }
                      onChange={(event) => handleTargetChange(event.target.value)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" && selectedRunnable) {
                          void runSelectedProbe();
                        }
                      }}
                    />
                  </label>
                ) : (
                  <div className="targetNote">
                    <ShieldCheck size={15} />
                    <span>{targetlessLabel(selectedProbe.id, locale)}</span>
                  </div>
                )}

                {selectedNeedsTarget && selectedAcceptsPort ? (
                  <label className="portInput">
                    <span>{locale === "vi" ? "Cổng" : "Port"}</span>
                    <input
                      name="diagnostic-port"
                      value={targetPort}
                      inputMode="numeric"
                      onChange={(event) => setTargetPort(event.target.value)}
                    />
                  </label>
                ) : null}

                <button
                  className={`primaryButton ${isLiveRunning ? "stopButton" : ""}`}
                  disabled={isLiveRunning ? isStoppingLive : !selectedRunnable || isBusy}
                  onClick={() =>
                    void (isLiveRunning ? stopLiveProbe() : runPrimaryAction())
                  }
                >
                  {isLiveRunning ? <Square size={14} /> : <Play size={15} />}
                  <span>
                    {isLiveRunning
                      ? isStoppingLive
                        ? locale === "vi"
                          ? "Đang dừng"
                          : "Stopping"
                        : locale === "vi"
                          ? "Dừng"
                          : "Stop"
                    : selectedRequiresRemote || selectedProbe.status === "planned"
                      ? locale === "vi"
                        ? "Kế hoạch"
                        : "Planned"
                      : usesCustomCommand
                        ? locale === "vi"
                          ? "Chạy command"
                          : "Run command"
                      : locale === "vi"
                        ? "Chạy"
                        : "Run"}
                  </span>
                </button>
              </div>

              {commandPreview ? (
                <details className="advancedRun">
                  <summary>
                    <span>{locale === "vi" ? "Tùy chọn nâng cao" : "Advanced options"}</span>
                    <ChevronDown size={14} />
                  </summary>
                  <div className="advancedRunBody">
                    <div className="commandActions">
                      <button
                        className="secondaryButton"
                        disabled={!selectedRunnable || isLiveRunning}
                        onClick={() => void runLiveProbe()}
                      >
                        <Activity size={15} />
                        <span>{locale === "vi" ? "Đầu ra trực tiếp" : "Live output"}</span>
                      </button>
                      <button
                        className="secondaryButton"
                        disabled={!selectedRunnable}
                        onClick={() => void openTerminalForProbe()}
                      >
                        <Terminal size={15} />
                        <span>{locale === "vi" ? "Mở CLI" : "CLI"}</span>
                      </button>
                    </div>
                    <label className="commandEditor">
                      <SquareTerminal size={14} />
                      <textarea
                        name="command-preview"
                        value={commandText}
                        spellCheck={false}
                        aria-label={locale === "vi" ? "Xem trước lệnh CLI" : "CLI command preview"}
                        onChange={(event) => {
                          setCommandText(event.target.value);
                          setCommandDirty(true);
                        }}
                      />
                    </label>
                  </div>
                </details>
              ) : null}
            </section>
          ) : null}

          {selectedRequiresRemote ? (
            <RemotePortCheckPanel
              locale={locale}
              target={target}
              port={targetPort}
            />
          ) : null}

          {liveLines.length > 0 || isLiveRunning ? (
            <section
              className={`liveConsolePanel ${
                isLiveRunning ? "running" : liveWasStopped ? "stopped" : "complete"
              }`}
            >
              <header>
                <div>
                  <span className="liveDot" />
                  <strong>
                    {isLiveRunning
                      ? locale === "vi"
                        ? "Live output đang chạy"
                        : "Live output running"
                      : liveWasStopped
                        ? locale === "vi"
                          ? "Live output đã dừng"
                          : "Live output stopped"
                        : locale === "vi"
                          ? "Live output đã xong"
                          : "Live output complete"}
                  </strong>
                </div>
                <em>
                  {liveLineCount} {locale === "vi" ? "dòng" : "lines"}
                </em>
              </header>
              <pre ref={liveConsoleRef}>{liveOutputText}</pre>
            </section>
          ) : null}

          <section
            className={`resultPanel ${verdict.status} ${
              selectedProbe ? `direction-${directionClass(selectedProbe.id)}` : ""
            }`}
          >
            <header>
              <div>
                <span className={`statusPill ${verdict.status}`}>
                  {verdictPillLabel(verdict, selectedProbe, locale)}
                </span>
                <strong>{verdict.title}</strong>
              </div>
              <button
                className="refreshButton"
                disabled={isNetworkSummaryLoading}
                onClick={() => void refreshNetworkSummary()}
                title={locale === "vi" ? "Cập nhật IP/DNS" : "Refresh IP/DNS"}
              >
                <RefreshCw size={14} />
              </button>
            </header>

            {verdict.detail ? <p className="verdictDetail">{verdict.detail}</p> : null}

            {resultRows.length > 0 ? (
              <dl className="factGrid">
                {resultRows.map((row) => (
                  <div key={`${row.label}-${row.value}`}>
                    <dt>{row.label}</dt>
                    <dd>{row.value}</dd>
                  </div>
                ))}
              </dl>
            ) : (
              <div className="emptyResult emptyState">
                <ListChecks size={20} />
                <strong>
                  {locale === "vi"
                    ? "Chưa có dữ liệu chẩn đoán"
                    : "No diagnostic data yet"}
                </strong>
                <span>
                  {selectedRequiresRemote
                    ? locale === "vi"
                      ? "Phần nhìn từ internet cần remote vantage/token, chưa chạy bằng lệnh local."
                      : "Outside visibility needs a remote vantage/token and is not faked locally."
                    : locale === "vi"
                      ? "Chạy check để xem verdict và các dòng tóm tắt."
                      : "Run a check to see the verdict and summary rows."}
                </span>
              </div>
            )}

            {result?.output.warnings && result.output.warnings.length > 0 ? (
              <div className="warningStrip">
                {result.output.warnings.map((warning, index) => (
                  <span key={`${warning.code ?? "warning"}-${index}`}>
                    {warning.message ?? warning.code ?? (locale === "vi" ? "Cảnh báo" : "Warning")}
                  </span>
                ))}
              </div>
            ) : null}

            {result?.interpretation?.next_actions &&
            result.interpretation.next_actions.length > 0 ? (
              <div className="nextActions">
                {result.interpretation.next_actions.map((action) => (
                  <button key={action.id} onClick={() => applyNextAction(action)}>
                    → {nextActionLabel(action, locale)}
                  </button>
                ))}
              </div>
            ) : null}

            <details className="rawOutput">
              <summary>
                <span>{locale === "vi" ? "Kết quả thô" : "Raw result"}</span>
                <ChevronDown size={14} />
              </summary>
              <pre>{rawOutput}</pre>
            </details>
          </section>
              </div>
            </div>
          )}

          <footer className="contextFooter">
            <span title={dnsTitle}>
              <Globe2 size={13} />
              IP {egressLabel}
            </span>
            <span title={dnsTitle}>
              <Database size={13} />
              DNS {formatDnsSummary(networkSummary, isNetworkSummaryLoading, locale)}
            </span>
            <span>
              <ListChecks size={13} />
              {catalog.length || "-"} {locale === "vi" ? "kiểm tra" : "checks"}
            </span>
          </footer>
          </section>
        </section>
      </section>
    </main>
  );
}

function CheckCard({
  probe,
  locale,
  active,
  workflowId,
  compact,
  disabled,
  onSelect,
}: {
  probe: ProbeDescriptor;
  locale: Locale;
  active: boolean;
  workflowId?: string;
  compact?: boolean;
  disabled?: boolean;
  onSelect: () => void;
}) {
  const copy = checkCopy(probe, locale, workflowId);
  return (
    <button
      type="button"
      className={`checkCard direction-${directionClass(probe.id)} ${
        active ? "active" : ""
      } ${compact ? "compact" : ""} ${
        disabled ? "planned" : ""
      }`}
      aria-pressed={active}
      aria-disabled={disabled || undefined}
      onClick={onSelect}
    >
      <small>{copy.eyebrow}</small>
      <strong>{copy.title}</strong>
      <span>{copy.subtitle}</span>
    </button>
  );
}

function PublicServicePlan({
  locale,
  networkSummary,
  result,
  onSelectProbe,
}: {
  locale: Locale;
  networkSummary: NetworkSummary | null;
  result: ProbeRunView | null;
  onSelectProbe: (probeId: string) => void;
}) {
  const items = publicIngressReadinessItems(locale, networkSummary, result);

  return (
    <section className="plannedPanel ingressReadinessPanel">
      <strong>
        {locale === "vi"
          ? "Sẵn sàng public ingress"
          : "Public ingress readiness"}
      </strong>
      <p>
        {locale === "vi"
          ? "Máy local có thể thu thập bằng chứng, còn bước kết luận Internet -> service cần remote vantage thật."
          : "Local checks gather evidence; the final Internet -> service verdict still needs a real outside vantage."}
      </p>

      <ul className="readinessList">
        {items.map((item) => {
          const actionProbeId = item.actionProbeId;
          return (
            <li key={item.id}>
              <span>
                <strong>{item.title}</strong>
                <small>{item.detail}</small>
              </span>
              <div className="readinessActions">
                {actionProbeId ? (
                  <button
                    className="miniActionButton"
                    onClick={() => onSelectProbe(actionProbeId)}
                  >
                    {item.actionLabel}
                  </button>
                ) : null}
                <em className={item.tone}>{item.status}</em>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function nmapHostViews(raw: unknown): NmapHostView[] {
  if (!raw || typeof raw !== "object") {
    return [];
  }
  const hosts = (raw as { hosts?: unknown }).hosts;
  if (!Array.isArray(hosts)) {
    return [];
  }

  return hosts
    .map((host): NmapHostView | null => {
      if (!host || typeof host !== "object") {
        return null;
      }
      const hostValue = (host as { host?: unknown }).host;
      const portsValue = (host as { ports?: unknown }).ports;
      if (typeof hostValue !== "string" || !Array.isArray(portsValue)) {
        return null;
      }
      const ports = portsValue
        .map((port): NmapOpenPortView | null => {
          if (!port || typeof port !== "object") {
            return null;
          }
          const value = port as {
            port?: unknown;
            proto?: unknown;
            service?: unknown;
            detail?: unknown;
          };
          if (typeof value.port !== "number") {
            return null;
          }
          return {
            port: value.port,
            proto: typeof value.proto === "string" ? value.proto : "tcp",
            service: typeof value.service === "string" ? value.service : "",
            detail: typeof value.detail === "string" ? value.detail : "",
          };
        })
        .filter((port): port is NmapOpenPortView => Boolean(port));

      return { host: hostValue, ports };
    })
    .filter((host): host is NmapHostView => host !== null && host.ports.length > 0);
}

function ManagedToolPage({
  locale,
  tool,
  toolId,
  interactionCatalog,
}: {
  locale: Locale;
  tool: ManagedToolDescriptor | undefined;
  toolId: string;
  interactionCatalog: InteractionCatalog | null;
}) {
  const effectiveTool = tool;
  const interactionNamespace = scannerNamespace(interactionCatalog, toolId);
  const isScanner = interactionCatalog
    ? Boolean(interactionNamespace)
    : [
        "nmap", "nuclei", "httpx", "naabu", "subfinder", "dnsx", "trippy", "nexttrace",
      ].includes(toolId);
  const [updatePlan, setUpdatePlan] = useState<ToolUpdatePlan | null>(null);
  const [updateError, setUpdateError] = useState<string | null>(null);
  const [runtime, setRuntime] = useState<ToolRuntimeStatus | null>(null);
  const [lifecycle, setLifecycle] = useState<ToolLifecyclePlan | null>(null);
  const [isLifecycleBusy, setIsLifecycleBusy] = useState(false);
  const [target, setTarget] = useState(
    toolId === "nuclei" || toolId === "httpx"
      ? "https://127.0.0.1"
      : toolId === "subfinder" || toolId === "dnsx"
        ? "example.com"
        : "127.0.0.1",
  );
  const [scanProfile, setScanProfile] = useState<ScannerProfileId>(
    defaultScannerProfile(toolId, interactionCatalog),
  );
  const [scanPorts, setScanPorts] = useState<ScannerPortsId>(defaultScannerPorts());
  const [customPorts, setCustomPorts] = useState("80,443");
  const [commandPreview, setCommandPreview] = useState<CommandPreview | null>(null);
  const [liveLines, setLiveLines] = useState<string[]>([]);
  const [scannerResult, setScannerResult] = useState<ScannerRunView | null>(null);
  const [scannerError, setScannerError] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const runIdRef = useRef<string | null>(null);

  useEffect(() => {
    setUpdatePlan(null);
    setUpdateError(null);
    setRuntime(null);
    setLifecycle(null);
    setTarget(toolId === "nuclei" ? "https://127.0.0.1" : "127.0.0.1");
    setScanProfile(defaultScannerProfile(toolId, interactionCatalog));
    setScanPorts(defaultScannerPorts());
    setCustomPorts("80,443");
    setCommandPreview(null);
    setLiveLines([]);
    setScannerResult(null);
    setScannerError(null);
    setIsRunning(false);
    setIsStopping(false);
    runIdRef.current = null;

    if (!isScanner || !hasTauriRuntime()) {
      return;
    }
    void Promise.all([
      invoke<ToolRuntimeStatus>("tool_runtime_status", { toolId }),
      invoke<ToolLifecyclePlan>("tool_lifecycle_plan", { toolId }),
    ])
      .then(([nextRuntime, nextLifecycle]) => {
        setRuntime(nextRuntime);
        setLifecycle(nextLifecycle);
      })
      .catch((err) => setScannerError(String(err)));
  }, [interactionCatalog, isScanner, toolId]);

  useEffect(() => {
    if (!isScanner || !hasTauriRuntime()) {
      return;
    }

    let disposed = false;
    let unlisten: (() => void) | null = null;
    const liveEvents = createLiveEventBuffer({
      appendLines: (nextLines) =>
        setLiveLines((lines) => boundLiveConsoleLines([...lines, ...nextLines])),
    });
    void listen<ProbeLiveEvent>("probe-live-output", (event) => {
      const payload = event.payload;
      if (payload.run_id !== runIdRef.current) {
        return;
      }
      liveEvents.handle(payload);
    }).then((cleanup) => {
      if (disposed) {
        cleanup();
      } else {
        unlisten = cleanup;
      }
    });

    return () => {
      disposed = true;
      liveEvents.dispose();
      unlisten?.();
    };
  }, [isScanner, toolId]);

  if (!effectiveTool) {
    return (
      <section className="externalScannerPanel managedToolPage">
        <header>
          <div>
            <strong>{toolId}</strong>
            <span>
              {locale === "vi"
                ? "Chưa có metadata cho tool này."
                : "No metadata is available for this tool yet."}
            </span>
          </div>
        </header>
      </section>
    );
  }

  const currentTool = effectiveTool;
  const scannerTarget = (): ProbeTargetInput => ({ type: "input", value: target.trim() });
  const scanProfiles = scannerProfileOptions(toolId, locale, interactionCatalog);
  const hasPorts = interactionCatalog
    ? scannerHasField(interactionCatalog, toolId, "ports")
    : toolId === "nmap" || toolId === "naabu";
  const targetField = scannerField(interactionCatalog, toolId, "target");
  const portsField = scannerField(interactionCatalog, toolId, "ports");
  const customPortsField = scannerField(interactionCatalog, toolId, "custom_ports");
  const resolvedScanPorts = hasPorts
    ? portsField?.kind === "ports"
      ? customPorts.trim() || undefined
      : scanPorts === "custom" ? customPorts.trim() : scanPorts
    : undefined;
  const packageStatusTone = runtime?.available ? "ready" : runtime ? "missing" : "waiting";
  const packageStatusTitle = runtime?.available
    ? locale === "vi" ? "Đã sẵn sàng" : "Ready"
    : runtime
      ? locale === "vi" ? "Chưa detect được" : "Not detected"
      : locale === "vi" ? "Chưa dò runtime" : "Not checked";
  const packageStatusDetail = packageStatusDetailLabel(runtime, lifecycle, locale);
  const packageModeLabel = locale === "vi" ? "Gói SonarNwork" : "SonarNwork package";
  const lifecycleActionLabel = isLifecycleBusy
    ? locale === "vi" ? "Đang xử lý..." : "Working..."
    : runtime?.available
      ? locale === "vi" ? "Cập nhật gói" : "Update package"
      : locale === "vi" ? "Cài vào app" : "Install in app";

  const nmapOpenHosts = scannerResult ? nmapHostViews(scannerResult.output.raw) : [];

  async function refreshRuntime() {
    setScannerError(null);
    try {
      const [nextRuntime, nextLifecycle] = await Promise.all([
        invoke<ToolRuntimeStatus>("tool_runtime_status", { toolId }),
        invoke<ToolLifecyclePlan>("tool_lifecycle_plan", { toolId }),
      ]);
      setRuntime(nextRuntime);
      setLifecycle(nextLifecycle);
    } catch (err) {
      setScannerError(String(err));
    }
  }

  async function runLifecycleAction() {
    if (!lifecycle?.install_supported || isLifecycleBusy) {
      return;
    }
    setScannerError(null);
    setIsLifecycleBusy(true);
    try {
      const command = runtime?.available ? "update_tool" : "install_tool";
      setRuntime(await invoke<ToolRuntimeStatus>(command, { toolId }));
      setLifecycle(await invoke<ToolLifecyclePlan>("tool_lifecycle_plan", { toolId }));
    } catch (err) {
      setScannerError(String(err));
    } finally {
      setIsLifecycleBusy(false);
    }
  }

  async function requestUpdatePlan() {
    setUpdateError(null);
    try {
      const plan = await invoke<ToolUpdatePlan>("tool_update_plan", {
        toolId: currentTool.id,
      });
      setUpdatePlan(plan);
    } catch (err) {
      if (isTauriRuntimeUnavailable(err)) {
        setUpdatePlan(fallbackToolUpdatePlan(currentTool));
        return;
      }
      setUpdateError(String(err));
    }
  }

  async function previewScanner() {
    setScannerError(null);
    setCommandPreview(null);
    try {
      setCommandPreview(
        await invoke<CommandPreview>("scanner_command", {
          toolId,
          target: scannerTarget(),
          scanProfile,
          scanPorts: resolvedScanPorts,
        }),
      );
    } catch (err) {
      setScannerError(String(err));
    }
  }

  async function runScanner() {
    if (isRunning) {
      return;
    }
    const runId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    runIdRef.current = runId;
    setScannerError(null);
    setScannerResult(null);
    setLiveLines([]);
    setIsRunning(true);
    setIsStopping(false);
    try {
      const result = await invoke<ScannerRunView>("run_scanner_live", {
        runId,
        toolId,
        target: scannerTarget(),
        scanProfile,
        scanPorts: resolvedScanPorts,
      });
      setScannerResult(result);
      setLiveLines((lines) =>
        boundLiveConsoleLines([
          ...(lines.length > 0 ? lines : capturedLiveLines(result.summary)),
          ...(lines.length > 0 && result.summary.truncated && result.summary.raw_output_path
            ? [`[output truncated; full log: ${result.summary.raw_output_path}]`]
            : []),
        ]),
      );
    } catch (err) {
      setScannerError(String(err));
    } finally {
      setIsRunning(false);
      setIsStopping(false);
      runIdRef.current = null;
    }
  }

  async function stopScanner() {
    const runId = runIdRef.current;
    if (!runId || isStopping) {
      return;
    }
    setIsStopping(true);
    try {
      const stopped = await invoke<boolean>("cancel_probe_live", { runId });
      setLiveLines((lines) => [
        ...lines,
        stopped ? "\n[stop] stop requested" : "\n[stop] no running process found",
      ]);
      if (!stopped) {
        setIsStopping(false);
      }
    } catch (err) {
      setScannerError(String(err));
      setIsStopping(false);
    }
  }

  async function openScannerCli() {
    setScannerError(null);
    try {
      await invoke("open_scanner_terminal", {
        toolId,
        target: scannerTarget(),
        scanProfile,
        scanPorts: resolvedScanPorts,
      });
    } catch (err) {
      setScannerError(String(err));
    }
  }

  return (
    <section className="externalScannerPanel managedToolPage">
      <header>
        <div>
          <strong>{currentTool.display_name}</strong>
          <span>{scannerIntro(toolId, locale)}</span>
        </div>
      </header>

      <div className="externalToolGrid single">
        <article className={`externalToolCard ${currentTool.id}`}>
          {isScanner ? (
            <div className="scannerRunner">
              <div
                className={`scannerPackageStatus ${packageStatusTone}`}
                data-tool-runtime={runtime?.available ? "available" : runtime ? "missing" : "checking"}
              >
                <div>
                  <span>{packageModeLabel}</span>
                  <strong>{packageStatusTitle}</strong>
                  <small>{packageStatusDetail}</small>
                </div>
                <div className="scannerPackageControls">
                  <em>{currentTool.display_name}</em>
                  <button
                    className="secondaryButton compact"
                    onClick={() => void refreshRuntime()}
                    disabled={isLifecycleBusy || isRunning}
                  >
                    <RefreshCw size={13} />
                    <span>{locale === "vi" ? "Dò lại" : "Refresh"}</span>
                  </button>
                  {lifecycle?.install_supported ? (
                    <button
                      className="secondaryButton compact"
                      onClick={() => void runLifecycleAction()}
                      disabled={isLifecycleBusy || isRunning}
                    >
                      <Download size={13} />
                      <span>{lifecycleActionLabel}</span>
                    </button>
                  ) : null}
                </div>
              </div>

              {runtime && !runtime.available ? (
                <div className="scannerSetupNotice">
                  <span>
                    {locale === "vi"
                      ? `${currentTool.display_name} chưa được cài để quét.`
                      : `${currentTool.display_name} is not installed for scanning.`}
                  </span>
                  <button
                    className="secondaryButton"
                    onClick={() => void runLifecycleAction()}
                    disabled={!lifecycle?.install_supported || isLifecycleBusy || isRunning}
                  >
                    <RefreshCw size={14} />
                    <span>
                      {isLifecycleBusy
                        ? locale === "vi" ? "Đang cài..." : "Installing..."
                        : locale === "vi" ? `Cài ${currentTool.display_name}` : `Install ${currentTool.display_name}`}
                    </span>
                  </button>
                </div>
              ) : null}

              <div className="scannerTargetRow">
                <label>
                  <span>{locale === "vi" ? "Mục tiêu" : "Target"}</span>
                  <input
                    name="scanner-target"
                    value={target}
                    onChange={(event) => {
                      setTarget(event.target.value);
                      setCommandPreview(null);
                    }}
                    placeholder={targetField?.placeholder ?? (toolId === "nuclei" ? "https://127.0.0.1" : "127.0.0.1")}
                    disabled={isRunning}
                  />
                </label>
              </div>

              {scanProfiles.length > 0 ? (
                <div className="scannerTargetRow">
                  <label>
                    <span>{locale === "vi" ? "Chế độ" : "Profile"}</span>
                    <select
                      name="scanner-profile"
                      value={scanProfile}
                      onChange={(event) => {
                        setScanProfile(event.target.value as ScannerProfileId);
                        setCommandPreview(null);
                      }}
                      disabled={isRunning}
                    >
                      {scanProfiles.map((profile) => (
                        <option key={profile.id} value={profile.id}>
                          {profile.label} — {profile.description}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
              ) : null}

              {hasPorts && portsField?.kind !== "ports" ? (
                <div className="scannerTargetRow">
                  <label>
                    <span>{locale === "vi" ? "Cổng" : "Ports"}</span>
                    <select
                      name="scanner-ports"
                      value={scanPorts}
                      onChange={(event) => {
                        setScanPorts(event.target.value as ScannerPortsId);
                        setCommandPreview(null);
                      }}
                      disabled={isRunning}
                    >
                      {(portsField?.choices.length
                        ? portsField.choices
                        : [
                            { value: "top", label: locale === "vi" ? "Port phổ biến" : "Common ports" },
                            { value: "all", label: locale === "vi" ? "Tất cả port" : "All ports" },
                            { value: "custom", label: locale === "vi" ? "Tự nhập" : "Custom" },
                          ]).map((choice) => (
                            <option key={choice.value} value={choice.value}>{choice.label}</option>
                          ))}
                    </select>
                  </label>
                  {scanPorts === "custom" ? (
                    <label>
                      <span>{locale === "vi" ? "Danh sách port" : "Port list"}</span>
                      <input
                        name="scanner-custom-ports"
                        value={customPorts}
                        onChange={(event) => {
                          setCustomPorts(event.target.value);
                          setCommandPreview(null);
                        }}
                        placeholder={customPortsField?.placeholder ?? "80,443,1000-2000"}
                        disabled={isRunning}
                      />
                    </label>
                  ) : null}
                </div>
              ) : null}

              {hasPorts && portsField?.kind === "ports" ? (
                <div className="scannerTargetRow">
                  <label>
                    <span>{portsField.label}</span>
                    <input
                      name="scanner-custom-ports"
                      value={customPorts}
                      onChange={(event) => {
                        setCustomPorts(event.target.value);
                        setCommandPreview(null);
                      }}
                      placeholder={portsField.placeholder ?? "80,443,1000-2000"}
                      disabled={isRunning}
                    />
                  </label>
                </div>
              ) : null}

              <div className="scannerActions">
                <button
                  className="secondaryButton"
                  onClick={() => void previewScanner()}
                  disabled={!target.trim() || isRunning}
                >
                  <SquareTerminal size={14} />
                  <span>{locale === "vi" ? "Xem lệnh" : "Show command"}</span>
                </button>
                <button
                  className="primaryButton"
                  onClick={() => void runScanner()}
                  disabled={!runtime?.available || !target.trim() || isRunning}
                >
                  <Play size={14} />
                  <span>
                    {isRunning
                      ? locale === "vi" ? "Đang quét..." : "Scanning..."
                      : locale === "vi" ? "Quét" : "Scan"}
                  </span>
                </button>
                <button
                  className="secondaryButton"
                  onClick={() => void openScannerCli()}
                  disabled={!target.trim() || isRunning}
                >
                  <Terminal size={14} />
                  <span>{locale === "vi" ? "Mở CLI" : "Open CLI"}</span>
                </button>
                <button
                  className="secondaryButton"
                  onClick={() => void stopScanner()}
                  disabled={!isRunning || isStopping}
                >
                  <Square size={14} />
                  <span>
                    {isStopping
                      ? locale === "vi" ? "Đang dừng..." : "Stopping..."
                      : locale === "vi" ? "Dừng" : "Stop"}
                  </span>
                </button>
              </div>
              {commandPreview ? (
                <div className="scannerCommandPreview">
                  <span>{locale === "vi" ? "Lệnh sẽ chạy" : "Command to run"}</span>
                  <code>{commandPreview.display}</code>
                </div>
              ) : null}
              {liveLines.length > 0 ? (
                <pre className="scannerLiveConsole">{liveLines.join("\n")}</pre>
              ) : null}
              {scannerResult ? (
                <div className="scannerResult">
                  <strong>
                    {scannerResult.output.summary ??
                      (locale === "vi" ? "Quét hoàn tất" : "Scanner completed")}
                  </strong>
                  {scannerResult.output.summary_rows.map((row) => (
                    <span key={row.label}>{row.label}: {row.value}</span>
                  ))}
                  {nmapOpenHosts.length > 0 ? (
                    <div className="nmapPortMap">
                      {nmapOpenHosts.map((host) => (
                        <div className="nmapHostRow" key={host.host}>
                          <strong>{host.host}</strong>
                          <div>
                            {host.ports.map((port) => (
                              <span className="openPortPill" key={`${host.host}-${port.proto}-${port.port}`}>
                                {port.port}/{port.proto}
                                {port.service ? <small>{port.service}</small> : null}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>
              ) : null}
              {scannerError ? <div className="scannerError">{scannerError}</div> : null}
            </div>
          ) : (
            <>
              <div className="toolActions">
                <button className="secondaryButton" onClick={() => void requestUpdatePlan()}>
                  <RefreshCw size={14} />
                  <span>{locale === "vi" ? "Cập nhật" : "Update"}</span>
                </button>
                <span>
                      {currentTool.update.update_supported
                        ? "GitHub/latest"
                        : locale === "vi"
                          ? "chỉ phát hiện"
                          : "detect-only"}
                </span>
              </div>
              {updatePlan ? (
                <div className="toolUpdatePlan">
                  <strong>{updatePlan.source_label}</strong>
                  <span>{updatePlan.update_note}</span>
                  <code>{updatePlan.latest_url}</code>
                </div>
              ) : null}
              {updateError ? <div className="toolUpdatePlan error">{updateError}</div> : null}
            </>
          )}
        </article>
      </div>
    </section>
  );
}

function OperationsPage({ locale }: { locale: Locale }) {
  const [captureRuntime, setCaptureRuntime] = useState<CaptureRuntime | null>(null);
  const [interfaces, setInterfaces] = useState<CaptureInterface[]>([]);
  const [interfaceId, setInterfaceId] = useState("");
  const [durationSeconds, setDurationSeconds] = useState("15");
  const [packetLimit, setPacketLimit] = useState("5000");
  const [captureResult, setCaptureResult] = useState<CaptureResult | null>(null);
  const [captureBusy, setCaptureBusy] = useState(false);
  const [inventory, setInventory] = useState<InventorySnapshot | null>(null);
  const [inventoryBusy, setInventoryBusy] = useState(false);
  const [monitors, setMonitors] = useState<MonitorConfig[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [monitorTarget, setMonitorTarget] = useState("1.1.1.1");
  const [monitorInterval, setMonitorInterval] = useState("60");
  const [latencyThreshold, setLatencyThreshold] = useState("500");
  const [lossThreshold, setLossThreshold] = useState("100");
  const [monitorBusy, setMonitorBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!hasTauriRuntime()) {
      const message = locale === "vi"
        ? "Các thao tác này cần ứng dụng desktop."
        : "These operations require the desktop app.";
      setCaptureRuntime({ available: false, error: message });
      setError(message);
      return;
    }
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void Promise.all([
      invoke<CaptureRuntime>("capture_runtime_status"),
      invoke<MonitorConfig[]>("list_monitors"),
      invoke<TimelineEvent[]>("list_timeline"),
    ])
      .then(async ([runtime, savedMonitors, events]) => {
        if (disposed) return;
        setCaptureRuntime(runtime);
        setMonitors(savedMonitors);
        setTimeline(events);
        if (runtime.available) {
          const availableInterfaces = await invoke<CaptureInterface[]>("list_capture_interfaces");
          if (!disposed) {
            setInterfaces(availableInterfaces);
            setInterfaceId(availableInterfaces[0]?.id ?? "");
          }
        }
      })
      .catch((reason) => !disposed && setError(String(reason)));
    void listen<TimelineEvent>("operations-event", ({ payload }) => {
      setTimeline((current) => [payload, ...current.filter((item) => item.id !== payload.id)].slice(0, 1000));
    }).then((stop) => {
      if (disposed) stop();
      else unlisten = stop;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [locale]);

  async function runCapture() {
    if (captureBusy || !interfaceId) return;
    setCaptureBusy(true);
    setError(null);
    try {
      const result = await invoke<CaptureResult>("capture_packets", {
        request: {
          interfaceId,
          durationSeconds: Number(durationSeconds),
          packetLimit: Number(packetLimit),
        },
      });
      setCaptureResult(result);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setCaptureBusy(false);
    }
  }

  async function refreshInventory() {
    if (inventoryBusy) return;
    setInventoryBusy(true);
    setError(null);
    try {
      setInventory(await invoke<InventorySnapshot>("collect_device_inventory"));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setInventoryBusy(false);
    }
  }

  async function addMonitor() {
    if (monitorBusy || !monitorTarget.trim()) return;
    setMonitorBusy(true);
    setError(null);
    try {
      const monitor = await invoke<MonitorConfig>("start_monitor", {
        request: {
          target: monitorTarget.trim(),
          intervalSeconds: Number(monitorInterval),
          latencyAlertMs: Number(latencyThreshold),
          lossAlertPercent: Number(lossThreshold),
        },
      });
      setMonitors((current) => [...current, monitor]);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setMonitorBusy(false);
    }
  }

  async function disableMonitor(id: string) {
    setError(null);
    try {
      await invoke("stop_monitor", { monitorId: id });
      setMonitors((current) => current.map((item) => item.id === id ? { ...item, enabled: false } : item));
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function clearEvents() {
    try {
      await invoke("clear_timeline");
      setTimeline([]);
    } catch (reason) {
      setError(String(reason));
    }
  }

  return (
    <section className="operationsPage">
      {error ? <div className="errorBanner" role="alert">{error}</div> : null}
      <div className="operationsGrid">
        <article className="operationsCard">
          <header><div><strong>{locale === "vi" ? "Bắt gói tin" : "Packet capture"}</strong><span>{locale === "vi" ? "TShark → pcapng → mở bằng Wireshark" : "TShark → pcapng → Wireshark handoff"}</span></div></header>
          <div className={`operationsRuntime ${captureRuntime?.available ? "ready" : "missing"}`}>
            <CircleDot size={16} />
            <span>{captureRuntime?.version ?? captureRuntime?.error ?? (locale === "vi" ? "Đang dò TShark…" : "Detecting TShark…")}</span>
          </div>
          <label><span>{locale === "vi" ? "Giao diện mạng" : "Interface"}</span><select name="capture-interface" value={interfaceId} onChange={(event) => setInterfaceId(event.target.value)} disabled={!captureRuntime?.available}>{interfaces.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label>
          <div className="operationsFields">
            <label><span>{locale === "vi" ? "Thời gian (giây)" : "Duration (seconds)"}</span><input name="capture-duration" type="number" min="1" max="300" value={durationSeconds} onChange={(event) => setDurationSeconds(event.target.value)} /></label>
            <label><span>{locale === "vi" ? "Giới hạn packet" : "Packet limit"}</span><input name="capture-packet-limit" type="number" min="1" max="100000" value={packetLimit} onChange={(event) => setPacketLimit(event.target.value)} /></label>
          </div>
          <button className="primaryRunButton" onClick={() => void runCapture()} disabled={!captureRuntime?.available || !interfaceId || captureBusy}><Play size={16} />{captureBusy ? (locale === "vi" ? "Đang bắt gói…" : "Capturing…") : (locale === "vi" ? "Bắt gói" : "Capture")}</button>
          {captureResult ? <div className="captureResult"><code>{captureResult.path}</code><span>{formatBytes(captureResult.bytes)}</span><button onClick={() => void invoke("open_capture_handoff", { path: captureResult.path })}>{locale === "vi" ? "Mở / bàn giao" : "Open / hand off"}</button></div> : null}
        </article>

        <article className="operationsCard">
          <header><div><strong>{locale === "vi" ? "Inventory thiết bị" : "Device inventory"}</strong><span>{locale === "vi" ? "Đọc neighbor table, không chủ động quét." : "Reads the neighbor table; no active scan."}</span></div><button onClick={() => void refreshInventory()} disabled={inventoryBusy}><RefreshCw size={15} />{inventoryBusy ? (locale === "vi" ? "Đang đọc…" : "Loading…") : (locale === "vi" ? "Làm mới" : "Refresh")}</button></header>
          <div className="inventoryTable">
            {inventoryBusy ? <div className="emptyState loading" role="status"><RefreshCw size={19} /><strong>{locale === "vi" ? "Đang đọc neighbor table" : "Reading neighbor table"}</strong><span>{locale === "vi" ? "Không thực hiện active scan." : "No active scan is performed."}</span></div> : inventory?.devices.length ? inventory.devices.map((device) => <div key={`${device.interface}-${device.ip}-${device.mac}`}><strong>{device.ip}</strong><span>{device.mac ?? "—"}</span><span>{device.interface ?? "—"}</span><em>{device.state}</em></div>) : <div className="emptyState"><Database size={20} /><strong>{locale === "vi" ? "Chưa có inventory" : "No inventory yet"}</strong><span>{locale === "vi" ? "Chọn Làm mới để đọc các neighbor đã biết." : "Refresh to read known neighbors."}</span></div>}
          </div>
        </article>

        <article className="operationsCard monitorCard">
          <header><div><strong>{locale === "vi" ? "Monitoring nền" : "Background monitoring"}</strong><span>{locale === "vi" ? "Chạy khi desktop app đang mở; cấu hình tự khôi phục." : "Runs while the desktop app is open; configurations resume automatically."}</span></div></header>
          <div className="operationsFields monitorFields">
            <label><span>{locale === "vi" ? "Đích" : "Target"}</span><input name="monitor-target" value={monitorTarget} onChange={(event) => setMonitorTarget(event.target.value)} /></label>
            <label><span>{locale === "vi" ? "Chu kỳ (giây)" : "Interval (seconds)"}</span><input name="monitor-interval" type="number" min="15" max="86400" value={monitorInterval} onChange={(event) => setMonitorInterval(event.target.value)} /></label>
            <label><span>{locale === "vi" ? "Cảnh báo độ trễ (ms)" : "Latency alert (ms)"}</span><input name="monitor-latency-threshold" type="number" min="1" max="120000" value={latencyThreshold} onChange={(event) => setLatencyThreshold(event.target.value)} /></label>
            <label><span>{locale === "vi" ? "Cảnh báo mất gói (%)" : "Loss alert (%)"}</span><input name="monitor-loss-threshold" type="number" min="0" max="100" value={lossThreshold} onChange={(event) => setLossThreshold(event.target.value)} /></label>
          </div>
          <button className="primaryRunButton" onClick={() => void addMonitor()} disabled={!monitorTarget.trim() || monitorBusy}><Activity size={16} />{locale === "vi" ? "Bắt đầu monitor" : "Start monitor"}</button>
          <div className="monitorList">{monitors.length ? monitors.map((monitor) => <div key={monitor.id}><div><strong>{monitor.target}</strong><span>{monitor.intervalSeconds}s · {monitor.latencyAlertMs}ms · {monitor.lossAlertPercent}%</span></div><em className={monitor.enabled ? "ready" : "stopped"}>{monitor.enabled ? (locale === "vi" ? "đang chạy" : "running") : (locale === "vi" ? "đã dừng" : "stopped")}</em>{monitor.enabled ? <button onClick={() => void disableMonitor(monitor.id)}><Square size={14} />{locale === "vi" ? "Dừng" : "Stop"}</button> : null}</div>) : <div className="emptyState"><Activity size={20} /><strong>{locale === "vi" ? "Chưa có monitor" : "No monitors yet"}</strong><span>{locale === "vi" ? "Nhập đích rồi bắt đầu." : "Enter a target, then start."}</span></div>}</div>
        </article>

        <article className="operationsCard timelineCard">
          <header><div><strong>{locale === "vi" ? "Dòng thời gian & cảnh báo" : "Timeline & alerts"}</strong><span>{timeline.length}/1000 {locale === "vi" ? "sự kiện" : "events"}</span></div><button onClick={() => void clearEvents()} disabled={!timeline.length}>{locale === "vi" ? "Xóa" : "Clear"}</button></header>
          <div className="timelineList">{timeline.length ? timeline.map((event) => <div key={event.id} className={event.severity}><CircleDot size={14} /><div><strong>{event.title}</strong><span>{event.detail}</span><small>{new Date(event.createdAt * 1000).toLocaleString()} · {event.kind}</small></div></div>) : <div className="emptyState"><CircleDot size={20} /><strong>{locale === "vi" ? "Dòng thời gian đang trống" : "Timeline is empty"}</strong><span>{locale === "vi" ? "Sự kiện monitor và cảnh báo sẽ xuất hiện ở đây." : "Monitor events and alerts will appear here."}</span></div>}</div>
        </article>
      </div>
    </section>
  );
}

function RemoteMeasurementPage({ locale }: { locale: Locale }) {
  const [kind, setKind] = useState<Exclude<RemoteMeasurementKind, "tcp_port">>("ping");
  const [target, setTarget] = useState("example.com");
  const [location, setLocation] = useState("world");
  const [limit, setLimit] = useState("1");
  const [token, setToken] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<GlobalpingMeasurementResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function runMeasurement() {
    if (isRunning || !target.trim()) {
      return;
    }
    setIsRunning(true);
    setError(null);
    setResult(null);
    try {
      setResult(
        await invoke<GlobalpingMeasurementResult>("run_globalping_measurement", {
          request: {
            kind,
            target: target.trim(),
            location: location.trim(),
            limit: Math.max(1, Math.min(3, Number.parseInt(limit, 10) || 1)),
            token: token.trim() || null,
          },
        }),
      );
    } catch (err) {
      setError(String(err));
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <section className="externalScannerPanel remoteExecutionPanel">
      <header>
        <div>
          <strong>Globalping</strong>
          <span>
            {locale === "vi"
              ? "Phép đo thật chạy từ tối đa 3 probe công khai bên ngoài mạng local."
              : "Real measurements run from at most three public probes outside the local network."}
          </span>
        </div>
      </header>

      <div className="remoteExecutionForm">
        <label>
          <span>{locale === "vi" ? "Phép đo" : "Measurement"}</span>
          <select value={kind} onChange={(event) => setKind(event.target.value as Exclude<RemoteMeasurementKind, "tcp_port">)} disabled={isRunning}>
            <option value="ping">Ping</option>
            <option value="traceroute">Traceroute</option>
            <option value="mtr">MTR</option>
            <option value="dns">DNS</option>
            <option value="http">HTTP</option>
          </select>
        </label>
        <label className="remoteTargetField">
          <span>{locale === "vi" ? "Mục tiêu public" : "Public target"}</span>
          <input
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder={kind === "http" ? "https://example.com/health" : "example.com"}
            disabled={isRunning}
          />
        </label>
        <label>
          <span>{locale === "vi" ? "Vị trí" : "Location"}</span>
          <input value={location} onChange={(event) => setLocation(event.target.value)} placeholder={locale === "vi" ? "toàn cầu, Việt Nam, AWS" : "world, Vietnam, AWS"} disabled={isRunning} />
        </label>
        <label>
          <span>{locale === "vi" ? "Số điểm đo" : "Probes"}</span>
          <select value={limit} onChange={(event) => setLimit(event.target.value)} disabled={isRunning}>
            <option value="1">1</option>
            <option value="2">2</option>
            <option value="3">3</option>
          </select>
        </label>
        <label className="remoteTokenField">
          <span>{locale === "vi" ? "API token (không bắt buộc)" : "API token (optional)"}</span>
          <input type="password" value={token} onChange={(event) => setToken(event.target.value)} autoComplete="off" disabled={isRunning} />
        </label>
      </div>

      <div className="remoteExecutionActions">
        <button className="primaryButton" onClick={() => void runMeasurement()} disabled={!target.trim() || isRunning}>
          <Globe2 size={15} />
          <span>{isRunning ? (locale === "vi" ? "Đang đo..." : "Measuring...") : (locale === "vi" ? "Đo từ xa" : "Run remote measurement")}</span>
        </button>
        <small>
          {locale === "vi"
            ? "Khi chạy, mục tiêu public được gửi tới Globalping; token chỉ nằm trong bộ nhớ và không được lưu."
            : "Running sends the public target to Globalping; the token stays in memory and is not persisted."}
        </small>
      </div>

      {error ? <div className="remotePlanStatus error">{error}</div> : null}
      {result ? <RemoteResultView locale={locale} result={result} /> : null}
    </section>
  );
}

function RemotePortCheckPanel({
  locale,
  target,
  port,
}: {
  locale: Locale;
  target: string;
  port: string;
}) {
  const [maxNodes, setMaxNodes] = useState("3");
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<RemotePortCheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const parsedPort = Number.parseInt(port, 10);
  const validPort = parsedPort >= 1 && parsedPort <= 65535;

  useEffect(() => {
    setResult(null);
    setError(null);
  }, [target, port]);

  async function runPortCheck() {
    if (!target.trim() || !validPort || isRunning) {
      return;
    }
    setIsRunning(true);
    setResult(null);
    setError(null);
    try {
      setResult(
        await invoke<RemotePortCheckResult>("run_remote_port_check", {
          request: {
            target: target.trim(),
            port: parsedPort,
            max_nodes: Math.max(1, Math.min(3, Number.parseInt(maxNodes, 10) || 1)),
          },
        }),
      );
    } catch (err) {
      setError(String(err));
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <section className="plannedPanel remotePlanPanel remoteExecutionPanel">
      <strong>{locale === "vi" ? "Kiểm tra TCP từ Internet thật" : "Real Internet TCP check"}</strong>
      <p>
        {locale === "vi"
          ? "Check-Host thử TCP handshake vào đúng host:port từ các node bên ngoài. Đây là bằng chứng remote, tách khỏi listener local."
          : "Check-Host attempts a TCP handshake to this exact host:port from outside nodes. This remote evidence is separate from local listeners."}
      </p>
      <div className="remotePortTarget">
        <code>{target.trim() || "public.example"}:{validPort ? parsedPort : locale === "vi" ? "cổng" : "port"}</code>
        <label>
          <span>{locale === "vi" ? "Số node" : "Nodes"}</span>
          <select value={maxNodes} onChange={(event) => setMaxNodes(event.target.value)} disabled={isRunning}>
            <option value="1">1</option>
            <option value="2">2</option>
            <option value="3">3</option>
          </select>
        </label>
      </div>
      <button className="primaryButton" onClick={() => void runPortCheck()} disabled={!target.trim() || !validPort || isRunning}>
        <ShieldCheck size={15} />
        <span>{isRunning ? (locale === "vi" ? "Đang kiểm tra..." : "Checking...") : (locale === "vi" ? "Kiểm tra từ ngoài" : "Check from outside")}</span>
      </button>
      {error ? <div className="remotePlanStatus error">{error}</div> : null}
      {result ? <RemoteResultView locale={locale} result={result} /> : null}
    </section>
  );
}

function RemoteResultView({
  locale,
  result,
}: {
  locale: Locale;
  result: GlobalpingMeasurementResult | RemotePortCheckResult;
}) {
  const resultUrl = "share_url" in result ? result.share_url : result.report_url;
  return (
    <div className="remoteResultView" data-remote-status={result.status}>
      <header>
        <div>
          <span>{result.provider === "globalping" ? "Globalping" : "Check-Host"}</span>
          <strong>{remoteStatusLabel(result.status, locale)}</strong>
        </div>
        <code>{result.id}</code>
      </header>
      <div className="remoteNodeGrid">
        {result.nodes.map((node, index) => (
          <article key={`${node.location}-${index}`} className={`remoteNodeResult ${node.status}`}>
            <strong>{node.location}</strong>
            {node.network ? <small>{node.network}</small> : null}
            <span>{node.summary}</span>
            <em>{node.status.replace(/_/g, " ")}</em>
            {node.raw_output ? <pre>{node.raw_output}</pre> : null}
          </article>
        ))}
      </div>
      <small>{resultUrl}</small>
    </div>
  );
}

function remoteStatusLabel(status: string, locale: Locale) {
  const labels: Record<string, Record<Locale, string>> = {
    finished: { en: "Finished", vi: "Hoàn tất" },
    open: { en: "Reachable", vi: "Truy cập được" },
    closed_or_filtered: { en: "Closed or filtered", vi: "Đóng hoặc bị lọc" },
    in_progress: { en: "Still running", vi: "Đang xử lý" },
  };
  return labels[status]?.[locale] ?? status.replace(/_/g, " ");
}

function RemotePlanPanel({
  locale,
  plan,
  loading,
  error,
}: {
  locale: Locale;
  plan: RemoteVantagePlan | null;
  loading: boolean;
  error: string | null;
}) {
  const facts = plan
    ? [
        [locale === "vi" ? "Nguồn đo" : "Provider", remoteProviderLabel(plan.request.provider)],
        [
          locale === "vi" ? "Phép đo" : "Measurement",
          remoteMeasurementLabel(plan.request.measurement),
        ],
        [locale === "vi" ? "Đích" : "Target", formatProbeTarget(plan.request.target)],
        plan.request.provider === "sonar_nwork_remote_scan"
          ? [
              locale === "vi" ? "Token phạm vi" : "Scope token",
              plan.request.scope_token ??
                (locale === "vi" ? "chờ bàn giao token" : "pending handoff"),
            ]
          : [
              locale === "vi" ? "Điểm đo" : "Vantage",
              locale === "vi" ? "ngoài mạng local" : "outside local network",
            ],
      ]
    : [];

  return (
    <section className="plannedPanel remotePlanPanel">
      <strong>
        {locale === "vi"
          ? "Kế hoạch Globalping cho public ingress"
          : "Globalping-style public ingress plan"}
      </strong>
      <p>
        {locale === "vi"
          ? "Netstat/listener chỉ là bằng chứng local. Public ingress cần điểm đo ngoài mạng thử TCP vào đúng host:port."
          : "Netstat/listeners are local evidence only. Public ingress needs an outside vantage to try TCP against the scoped host:port."}
      </p>

      {loading ? (
        <div className="remotePlanStatus">
          {locale === "vi" ? "Đang tạo kế hoạch..." : "Preparing plan..."}
        </div>
      ) : null}

      {error ? <div className="remotePlanStatus error">{error}</div> : null}

      {plan ? (
        <>
          <dl className="remotePlanFacts">
            {facts.map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>

          {plan.warning ? <div className="remotePlanStatus">{plan.warning}</div> : null}

          <ul>
            {plan.allowed_probe_ids.map((probeId) => (
              <li key={probeId}>
                <span>{probeId}</span>
                <em>{locale === "vi" ? "từ ngoài" : "remote"}</em>
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </section>
  );
}

function publicIngressReadinessItems(
  locale: Locale,
  networkSummary: NetworkSummary | null,
  result: ProbeRunView | null,
): IngressReadinessItem[] {
  const remoteAction = locale === "vi" ? "Tạo kế hoạch" : "Plan";
  const localStateAction = locale === "vi" ? "Kiểm tra LAN" : "Check LAN";
  const listenersAction = locale === "vi" ? "Kiểm tra port" : "Check ports";
  const reachabilityAction = locale === "vi" ? "Thử TCP" : "Test TCP";
  const egressIp = networkSummary?.egressIp?.trim() ?? "";
  const localIps = summaryRowValue(result, "Local IPs");
  const publicBinds = summaryRowValue(result, "Public binds");
  const connected = summaryRowValue(result, "Connected");

  return [
    {
      id: "remote-vantage",
      title:
        locale === "vi"
          ? "Điểm đo bên ngoài cho dịch vụ public"
          : "Remote vantage for public ingress",
      detail:
        locale === "vi"
          ? "Tạo bước bàn giao để máy bên ngoài thử kết nối vào host:port này."
          : "Prepare a handoff so an outside host can test this host:port.",
      status: locale === "vi" ? "sẵn sàng" : "ready",
      tone: "ready",
      actionLabel: remoteAction,
      actionProbeId: "public.port_check",
    },
    natReadinessItem(locale, egressIp, localIps, localStateAction),
    {
      id: "upnp",
      title: locale === "vi" ? "Trạng thái UPnP" : "UPnP state",
      detail:
        locale === "vi"
          ? "Chưa có probe UPnP local; cần bổ sung discovery IGD/PCP/NAT-PMP."
          : "No local UPnP probe yet; needs IGD/PCP/NAT-PMP discovery.",
      status: locale === "vi" ? "kế tiếp" : "next",
      tone: "planned",
    },
    firewallReadinessItem(locale, publicBinds, connected, listenersAction, reachabilityAction),
    {
      id: "scope-token",
      title:
        locale === "vi"
          ? "Token bàn giao có phạm vi"
          : "Scoped token handoff",
      detail:
        locale === "vi"
          ? "Quét từ ngoài chỉ được tạo sau khi chọn target và port rõ ràng."
          : "Remote-scan is prepared only after an explicit host and port are selected.",
      status: locale === "vi" ? "cần target" : "needs target",
      tone: "waiting",
      actionLabel: remoteAction,
      actionProbeId: "public.port_check",
    },
  ];
}

function natReadinessItem(
  locale: Locale,
  egressIp: string,
  localIps: string | null,
  actionLabel: string,
): IngressReadinessItem {
  if (egressIp && isCgnatIp(egressIp)) {
    return {
      id: "nat-cgnat",
      title: locale === "vi" ? "Gợi ý NAT / CGNAT" : "NAT / CGNAT hint",
      detail:
        locale === "vi"
          ? `Egress ${egressIp} nằm trong 100.64.0.0/10; public ingress có thể bị CGNAT chặn.`
          : `Egress ${egressIp} is inside 100.64.0.0/10; public ingress may be blocked by CGNAT.`,
      status: locale === "vi" ? "cảnh báo" : "warning",
      tone: "warning",
      actionLabel,
      actionProbeId: "local.network_state",
    };
  }

  if (egressIp && localIps && containsPrivateIp(localIps)) {
    return {
      id: "nat-cgnat",
      title: locale === "vi" ? "Gợi ý NAT / CGNAT" : "NAT / CGNAT hint",
      detail:
        locale === "vi"
          ? `Máy có IP private, egress là ${egressIp}; cần port-forward/router rule để mở ingress.`
          : `This host has a private IP and egresses as ${egressIp}; inbound needs a router or port-forward rule.`,
      status: locale === "vi" ? "có NAT" : "NAT likely",
      tone: "warning",
      actionLabel,
      actionProbeId: "local.network_state",
    };
  }

  if (egressIp) {
    return {
      id: "nat-cgnat",
      title: locale === "vi" ? "Gợi ý NAT / CGNAT" : "NAT / CGNAT hint",
      detail:
        locale === "vi"
          ? `Đã thấy public egress ${egressIp}; chạy LAN check để so với IP local.`
          : `Public egress ${egressIp} is visible; run LAN check to compare it with local addresses.`,
      status: locale === "vi" ? "một phần" : "partial",
      tone: "waiting",
      actionLabel,
      actionProbeId: "local.network_state",
    };
  }

  return {
    id: "nat-cgnat",
    title: locale === "vi" ? "Gợi ý NAT / CGNAT" : "NAT / CGNAT hint",
    detail:
      locale === "vi"
        ? "Cần IP egress và IP local để phân biệt direct, NAT, hay CGNAT."
        : "Needs egress and local IP evidence to separate direct, NAT, and CGNAT cases.",
    status: locale === "vi" ? "chờ dữ liệu" : "waiting",
    tone: "waiting",
    actionLabel,
    actionProbeId: "local.network_state",
  };
}

function firewallReadinessItem(
  locale: Locale,
  publicBinds: string | null,
  connected: string | null,
  listenersAction: string,
  reachabilityAction: string,
): IngressReadinessItem {
  if (connected?.toLowerCase() === "yes") {
    return {
      id: "firewall",
      title:
        locale === "vi"
          ? "Gợi ý allow/deny của tường lửa"
          : "Firewall allow/deny hint",
      detail:
        locale === "vi"
          ? "TCP local connect thành công; nếu remote fail thì xem router/firewall/WAN rule."
          : "Local TCP connect succeeds; if remote fails, inspect router, firewall, or WAN rules.",
      status: locale === "vi" ? "local ổn" : "local ok",
      tone: "ready",
      actionLabel: reachabilityAction,
      actionProbeId: "connectivity.reachability",
    };
  }

  if (connected?.toLowerCase() === "no") {
    return {
      id: "firewall",
      title:
        locale === "vi"
          ? "Gợi ý allow/deny của tường lửa"
          : "Firewall allow/deny hint",
      detail:
        locale === "vi"
          ? "TCP local connect fail; sửa service/firewall local trước khi thử remote."
          : "Local TCP connect fails; fix the service or local firewall before remote testing.",
      status: locale === "vi" ? "chặn local" : "local blocked",
      tone: "warning",
      actionLabel: reachabilityAction,
      actionProbeId: "connectivity.reachability",
    };
  }

  if (publicBinds && positiveIntegerText(publicBinds)) {
    return {
      id: "firewall",
      title:
        locale === "vi"
          ? "Gợi ý allow/deny của tường lửa"
          : "Firewall allow/deny hint",
      detail:
        locale === "vi"
          ? `${publicBinds} listener bind mọi interface; cần TCP check và remote vantage để kết luận.`
          : `${publicBinds} listener(s) bind all interfaces; use TCP check and remote vantage to finish the verdict.`,
      status: locale === "vi" ? "có listener" : "listener found",
      tone: "ready",
      actionLabel: reachabilityAction,
      actionProbeId: "connectivity.reachability",
    };
  }

  return {
    id: "firewall",
    title:
      locale === "vi"
        ? "Gợi ý allow/deny của tường lửa"
        : "Firewall allow/deny hint",
    detail:
      locale === "vi"
        ? "Chạy listening ports để biết service có bind đúng interface không."
        : "Run listening ports to see whether the service binds the right interface.",
    status: locale === "vi" ? "chờ dữ liệu" : "waiting",
    tone: "waiting",
    actionLabel: listenersAction,
    actionProbeId: "local.listening_ports",
  };
}

function uiWorkflows(
  coreWorkflows: WorkflowDescriptor[],
  catalog: ProbeDescriptor[],
): WorkflowDescriptor[] {
  const publicCheckIds = [
    "connectivity.ping",
    "connectivity.reachability",
    "web.http_probe",
    "web.tls_cert",
  ].filter((probeId) => catalog.some((probe) => probe.id === probeId));
  const workflows = coreWorkflows
    .filter((workflow) => workflow.id !== "slow_network")
    .map((workflow) =>
      workflow.id === "public_service"
        ? {
            ...workflow,
            target: { type: "input" as const, value: "" },
            primary_probe_ids: publicCheckIds,
            advanced_probe_ids: [],
          }
        : workflow,
    );
  for (const item of MANAGED_TOOL_WORKFLOWS) {
    if (!workflows.some((workflow) => workflow.id === item.workflowId)) {
      workflows.push(managedToolWorkflow(item.workflowId));
    }
  }

  if (
    catalog.some((probe) => probe.id === "recon.whois_rdap") &&
    !workflows.some((workflow) => workflow.id === "public_lookup")
  ) {
    workflows.push({
      id: "public_lookup",
      title_key: "workflow.public_lookup.title",
      description_key: "workflow.public_lookup.description",
      target: { type: "input", value: "" },
      primary_probe_ids: ["recon.whois_rdap"],
      advanced_probe_ids: [],
    });
  }

  return workflows;
}

function managedToolWorkflow(workflowId: string): WorkflowDescriptor {
  return {
    id: workflowId,
    title_key: `workflow.${workflowId}.title`,
    description_key: `workflow.${workflowId}.description`,
    target: { type: "local_machine" },
    primary_probe_ids: [],
    advanced_probe_ids: [],
  };
}

function toolIdForWorkflow(workflowId: string | undefined) {
  return (
    MANAGED_TOOL_WORKFLOWS.find((item) => item.workflowId === workflowId)?.toolId ??
    null
  );
}

function managedToolForId(tools: ManagedToolDescriptor[], toolId: string) {
  return tools.find((tool) => tool.id === toolId);
}

function preferredProbeId(
  workflow: WorkflowDescriptor | undefined,
  catalog: ProbeDescriptor[],
) {
  if (!workflow) {
    return catalog[0]?.id;
  }

  const preferred: Record<string, string[]> = {
    internet_path: ["public.egress_check", "connectivity.ping"],
    local_network: ["local.network_state"],
    public_service: ["connectivity.ping"],
    public_lookup: ["recon.whois_rdap"],
  };
  const ids = [...(preferred[workflow.id] ?? []), ...workflow.primary_probe_ids, ...workflow.advanced_probe_ids];
  return ids.find((id) => catalog.some((probe) => probe.id === id));
}

function defaultTargetForWorkflow(workflowId: string) {
  if (workflowId === "public_lookup") {
    return "example.com";
  }
  if (workflowId === "public_service") {
    return "";
  }
  return "1.1.1.1";
}

function workflowCopy(workflowId: string | undefined, locale: Locale) {
  return (
    WORKFLOW_TABS[workflowId ?? "internet_path"]?.[locale] ??
    WORKFLOW_TABS.internet_path[locale]
  );
}

function checkCopy(probe: ProbeDescriptor, locale: Locale, workflowId?: string) {
  const contextual = contextualCheckCopy(probe.id, locale, workflowId);
  if (contextual) {
    return contextual;
  }

  return (
    CHECK_COPY[probe.id]?.[locale] ?? {
      eyebrow: directionLabel(probe.id, locale),
      title: probe.name,
      subtitle: probe.description,
    }
  );
}

function contextualCheckCopy(probeId: string, locale: Locale, workflowId?: string) {
  if (workflowId !== "public_service") {
    return null;
  }

  const publicServiceCopy: Record<
    string,
    Record<Locale, { eyebrow: string; title: string; subtitle: string }>
  > = {
    "connectivity.ping": {
      en: {
        eyebrow: "Public check",
        title: "Public ping",
        subtitle: "Latency and packet loss to the host",
      },
      vi: {
        eyebrow: "Kiểm tra public",
        title: "Ping public",
        subtitle: "Độ trễ và mất gói tới máy chủ",
      },
    },
    "connectivity.reachability": {
      en: {
        eyebrow: "Public check",
        title: "Public port check",
        subtitle: "Try a TCP connection to host:port",
      },
      vi: {
        eyebrow: "Kiểm tra public",
        title: "Kiểm tra port public",
        subtitle: "Thử kết nối TCP tới host:port",
      },
    },
    "web.http_probe": {
      en: {
        eyebrow: "Public check",
        title: "Public HTTP check",
        subtitle: "Status and response from the website",
      },
      vi: {
        eyebrow: "Kiểm tra public",
        title: "Kiểm tra HTTP public",
        subtitle: "Trạng thái và phản hồi của website",
      },
    },
    "web.tls_cert": {
      en: {
        eyebrow: "Public check",
        title: "Public TLS check",
        subtitle: "HTTPS certificate and expiry",
      },
      vi: {
        eyebrow: "Kiểm tra public",
        title: "Kiểm tra TLS public",
        subtitle: "Chứng chỉ HTTPS và thời hạn",
      },
    },
  };

  return publicServiceCopy[probeId]?.[locale] ?? null;
}

function directionLabel(probeId: string, locale: Locale) {
  if (probeId.startsWith("local.")) {
    return locale === "vi" ? "máy local" : "local host";
  }
  if (probeId === "connectivity.route_check") {
    return locale === "vi" ? "bảng định tuyến local" : "local route table";
  }
  if (probeId === "public.egress_check" || probeId === "dns.leak_check") {
    return locale === "vi" ? "máy local → internet" : "local → internet";
  }
  if (probeId === "public.port_check") {
    return locale === "vi" ? "dịch vụ public" : "public ingress";
  }
  if (probeId.startsWith("recon.")) {
    return locale === "vi" ? "bản ghi public" : "public records";
  }
  if (probeId === "connectivity.reachability") {
    return locale === "vi" ? "kết nối local" : "local reachability";
  }
  if (probeId === "dns.lookup") {
    return locale === "vi" ? "máy local → DNS" : "local → DNS";
  }
  if (probeId.startsWith("web.http")) {
    return locale === "vi" ? "máy local → HTTP" : "local → HTTP";
  }
  if (probeId.startsWith("web.tls")) {
    return locale === "vi" ? "máy local → TLS" : "local → TLS";
  }
  return locale === "vi" ? "local → đích" : "local → target";
}

function targetlessLabel(probeId: string, locale: Locale) {
  if (probeId.startsWith("local.")) {
    return locale === "vi"
      ? "Local host - không cần target"
      : "Local host - no target needed";
  }
  if (probeId === "connectivity.route_check") {
    return locale === "vi"
      ? "Local route table - không cần target"
      : "Local route table - no target needed";
  }
  return locale === "vi"
    ? "Local → Internet - không cần target"
    : "Local → Internet - no target needed";
}

function directionClass(probeId: string) {
  if (
    probeId.startsWith("local.") ||
    LOCAL_DIRECTION_PROBE_IDS.has(probeId)
  ) {
    return "local";
  }
  if (probeId === "public.port_check") {
    return "public";
  }
  if (probeId.startsWith("recon.")) {
    return "lookup";
  }
  return "outbound";
}

function statusLabel(status: VerdictStatus | ProbeStatus, locale: Locale) {
  const labels = {
    en: {
      ok: "OK",
      warning: "Warning",
      failed: "Failed",
      unknown: "Planned",
      ready: "Ready",
      planned: "Planned",
      disabled: "Disabled",
    },
    vi: {
      ok: "Ổn",
      warning: "Cảnh báo",
      failed: "Lỗi",
      unknown: "Kế hoạch",
      ready: "Sẵn sàng",
      planned: "Kế hoạch",
      disabled: "Tắt",
    },
  } as const;

  return labels[locale][status];
}

function plannedLabel(locale: Locale) {
  return locale === "vi" ? "Kế hoạch" : "Planned";
}

function verdictPillLabel(
  verdict: ResultVerdict,
  selectedProbe: ProbeDescriptor | undefined,
  locale: Locale,
) {
  if (
    verdict.status === "unknown" &&
    selectedProbe &&
    (selectedProbe.status === "planned" || probeRequiresRemoteVantage(selectedProbe.id))
  ) {
    return plannedLabel(locale);
  }

  if (verdict.status === "unknown") {
    return locale === "vi" ? "Chưa chạy" : "Not run";
  }

  return statusLabel(verdict.status, locale);
}

export function resultVerdict(
  result: ProbeRunView | null,
  liveLines: string[],
  liveExitCode: number | null,
  isLiveRunning: boolean,
  liveWasStopped: boolean,
  selectedProbe: ProbeDescriptor | undefined,
  locale: Locale,
): ResultVerdict {
  if (result?.interpretation?.verdict) {
    return result.interpretation.verdict;
  }
  const resolvedLiveExitCode = liveExitCode ?? liveExitCodeFromLines(liveLines);
  if (
    liveLines.length > 0 &&
    !isLiveRunning &&
    resolvedLiveExitCode !== null &&
    resolvedLiveExitCode !== 0
  ) {
    return {
      status: "failed",
      title:
        locale === "vi"
          ? `Lệnh live kết thúc với exit code ${resolvedLiveExitCode}.`
          : `Live command exited with code ${resolvedLiveExitCode}.`,
      detail:
        locale === "vi"
          ? "Xem raw output bên dưới để biết lỗi từ công cụ hệ thống."
          : "Inspect the raw output below for the underlying tool error.",
    };
  }
  if (liveWasStopped && liveLines.length > 0 && !isLiveRunning) {
    return {
      status: "warning",
      title:
        locale === "vi"
          ? "Đã dừng lệnh. Giữ output đã nhận được."
          : "Command stopped. Partial output is kept.",
      detail:
        locale === "vi"
          ? "Phần raw output bên dưới là dữ liệu đã stream trước khi dừng."
          : "The raw output below contains the data streamed before stop.",
    };
  }
  if (isLiveRunning) {
    return {
      status: "unknown",
      title: locale === "vi" ? "Lệnh live đang chạy." : "Live command is running.",
      detail: null,
    };
  }
  if (liveLines.length > 0) {
    if (resolvedLiveExitCode === 0) {
      return {
        status: "ok",
        title: locale === "vi" ? "Lệnh live đã hoàn tất." : "Live command completed.",
        detail: null,
      };
    }
    // Completed but no confirmed success code — never claim green (E3).
    return {
      status: "unknown",
      title:
        locale === "vi"
          ? "Lệnh live đã kết thúc nhưng chưa xác nhận được thành công."
          : "Live command finished without a confirmed success code.",
      detail:
        locale === "vi"
          ? "Không thấy mã thoát 0 rõ ràng — xem raw output bên dưới để kiểm chứng."
          : "No explicit exit code 0 — inspect the raw output below to confirm.",
    };
  }
  if (selectedProbe && probeRequiresRemoteVantage(selectedProbe.id)) {
    return {
      status: "unknown",
      title:
        locale === "vi"
          ? "Kiểm tra này đang ở kế hoạch remote-scan."
          : "This check is planned for remote-scan.",
      detail: null,
    };
  }
  return {
    status: "unknown",
    title: locale === "vi" ? "Chưa có kết quả." : "No result yet.",
    detail: null,
  };
}

export function liveExitCodeFromLines(liveLines: string[]) {
  for (let index = liveLines.length - 1; index >= 0; index -= 1) {
    const match = liveLines[index].match(
      /\[exit\]\s+code\s+(-?\d+)|\[done\].*exited with\s+(-?\d+)/i,
    );
    if (match) {
      return Number(match[1] ?? match[2]);
    }
  }
  return null;
}

function resultSummaryRows(result: ProbeRunView | null, locale: Locale): SummaryRow[] {
  if (!result) {
    return [];
  }

  const rows =
    result.interpretation?.summary_rows && result.interpretation.summary_rows.length > 0
      ? result.interpretation.summary_rows
      : result.output.summary_rows ?? [];

  return rows.map((row) => ({
    label: SUMMARY_LABELS[row.label]?.[locale] ?? row.label,
    value: clipSummaryValue(row.value),
  }));
}

function nextActionLabel(action: NextAction, locale: Locale) {
  return NEXT_ACTION_COPY[action.label_key]?.[locale] ?? action.label_key;
}

function fallbackWorkflows(): WorkflowDescriptor[] {
  return [
    {
      id: "local_network",
      title_key: "workflow.local_network.title",
      description_key: "workflow.local_network.description",
      target: { type: "local_machine" },
      primary_probe_ids: ["local.network_state", "local.listening_ports"],
      advanced_probe_ids: ["connectivity.route_check"],
    },
    {
      id: "internet_path",
      title_key: "workflow.internet_path.title",
      description_key: "workflow.internet_path.description",
      target: { type: "current_internet_path" },
      primary_probe_ids: [
        "public.egress_check",
        "connectivity.ping",
        "connectivity.traceroute",
        "web.http_probe",
      ],
      advanced_probe_ids: [
        "dns.leak_check",
        "dns.lookup",
        "connectivity.mtr",
        "connectivity.path_mtu",
        "web.tls_cert",
      ],
    },
    {
      id: "public_service",
      title_key: "workflow.public_service.title",
      description_key: "workflow.public_service.description",
      target: { type: "input", value: "" },
      primary_probe_ids: [
        "connectivity.ping",
        "connectivity.reachability",
        "web.http_probe",
        "web.tls_cert",
      ],
      advanced_probe_ids: [],
    },
  ];
}

function fallbackAppInfo(): AppInfo {
  return {
    name: "SonarNwork",
    core_crate: "sonar-core",
    version: "dev-browser",
    contract: "Browser preview is using local fallback metadata.",
  };
}

function fallbackRemotePlan(target: ProbeTargetInput): RemoteVantagePlan {
  return {
    request: {
      provider: "sonar_nwork_remote_scan",
      measurement: "tcp_port",
      target,
      locations: [],
      scope_token: null,
    },
    allowed_probe_ids: ["public.port_check"],
    warning:
      "Browser preview cannot call the remote TCP provider; run the desktop app for an outside port check.",
  };
}

function fallbackManagedTools(): ManagedToolDescriptor[] {
  return [
    {
      id: "nmap",
      display_name: "Nmap",
      source: "nmap_org",
      install_strategy: "system_installer",
      risk: "active_scanner",
      category: "port_discovery",
      capabilities: ["port_scan"],
      target_kinds: ["host", "ip_address", "domain", "url", "network_range"],
      interactions: ["preview", "run_in_app", "open_in_cli", "stop", "structured_output"],
      scope_requirement: "active_target",
      default_enabled: false,
      notes:
        "SonarNwork scanner package; the app manages detection and launch, while the official Nmap installer may request Npcap or system permission.",
      update: {
        source_label: "Nmap.org",
        source_url: "https://nmap.org/download.html",
        latest_url: "https://nmap.org/download.html",
        update_supported: true,
        update_note:
          "Install or update from SonarNwork using the official Nmap installer, then refresh package detection.",
      },
    },
    {
      id: "nuclei",
      display_name: "Nuclei",
      source: "project_discovery",
      install_strategy: "managed_download",
      risk: "intrusive_scanner",
      category: "vuln_scanning",
      capabilities: ["template_scan"],
      target_kinds: ["url"],
      interactions: ["preview", "run_in_app", "open_in_cli", "stop", "structured_output"],
      scope_requirement: "intrusive_target",
      default_enabled: false,
      notes:
        "Template scanning is kept out of beginner defaults and uses bounded profiles.",
      update: {
        source_label: "GitHub: projectdiscovery/nuclei",
        source_url: "https://github.com/projectdiscovery/nuclei",
        latest_url: "https://github.com/projectdiscovery/nuclei/releases/latest",
        update_supported: true,
        update_note:
          "Update from ProjectDiscovery GitHub releases; run templates with bounded profiles.",
      },
    },
  ];
}

function fallbackToolUpdatePlan(tool: ManagedToolDescriptor): ToolUpdatePlan {
  return {
    tool_id: tool.id,
    display_name: tool.display_name,
    source_label: tool.update.source_label,
    source_url: tool.update.source_url,
    latest_url: tool.update.latest_url,
    update_supported: tool.update.update_supported,
    update_note: tool.update.update_note,
  };
}

function fallbackCatalog(): ProbeDescriptor[] {
  return [
    fallbackProbe("local.network_state", "Local network state", "Interfaces, gateway, DNS, and route basics on local host.", "local_network", "passive"),
    fallbackProbe("local.listening_ports", "Listening ports", "Local TCP listeners and bind addresses.", "local_network", "passive"),
    fallbackProbe("public.egress_check", "Egress IP + DNS", "Public IP and current internet path checks.", "public_exposure", "passive"),
    fallbackProbe("dns.leak_check", "DNS leak check", "Configured DNS and observed resolver path.", "dns", "passive"),
    fallbackProbe("connectivity.ping", "Ping", "Quick latency and packet-loss check for a target.", "connectivity", "safe_active"),
    fallbackProbe("connectivity.traceroute", "Traceroute", "Route and hop visibility for a target.", "connectivity", "safe_active"),
    fallbackProbe("connectivity.fast_trace", "Fast trace", "Short route sample for quick triage.", "connectivity", "safe_active"),
    fallbackProbe("connectivity.mtr", "Loss by hop", "Latency and loss samples per hop.", "connectivity", "safe_active"),
    fallbackProbe("connectivity.path_mtu", "Path MTU", "Estimate path MTU toward a target.", "connectivity", "safe_active"),
    fallbackProbe("connectivity.route_check", "Route print", "Local route table and default gateway.", "connectivity", "passive"),
    fallbackProbe("connectivity.reachability", "Reachability", "Check whether a host and port can be reached.", "connectivity", "safe_active"),
    fallbackProbe("public.port_check", "Public port check", "Outside vantage check for a scoped public service.", "public_exposure", "safe_active", "planned"),
    fallbackProbe("web.http_probe", "HTTP check", "HTTP status and response summary.", "web_tls", "safe_active"),
    fallbackProbe("web.tls_cert", "TLS certificate", "TLS handshake and certificate metadata.", "web_tls", "safe_active"),
    fallbackProbe("dns.lookup", "DNS lookup", "Resolve records through the local resolver.", "dns", "passive"),
    fallbackProbe("recon.whois_rdap", "RDAP lookup", "Public ownership and registration lookup.", "recon", "passive"),
  ];
}

function fallbackProbe(
  id: string,
  name: string,
  description: string,
  category: ProbeDescriptor["category"],
  risk: string,
  status: ProbeStatus = "ready",
): ProbeDescriptor {
  return {
    id,
    name,
    description,
    category,
    status,
    risk,
    requirements: [],
  };
}

function remoteProviderLabel(provider: RemoteVantageProvider) {
  const labels: Record<RemoteVantageProvider, string> = {
    globalping: "Globalping",
    sonar_nwork_remote_scan: "SonarNwork remote-scan",
  };
  return labels[provider] ?? provider;
}

function remoteMeasurementLabel(measurement: RemoteMeasurementKind) {
  const labels: Record<RemoteMeasurementKind, string> = {
    ping: "Ping",
    traceroute: "Traceroute",
    dns: "DNS",
    mtr: "MTR",
    http: "HTTP",
    tcp_port: "TCP port",
  };
  return labels[measurement] ?? measurement;
}

function formatProbeTarget(target: ProbeTargetInput) {
  if (target.type === "input") {
    return target.value;
  }
  if (target.type === "local_machine") {
    return "local machine";
  }
  return "current internet path";
}

function installStrategyLabel(strategy: ToolInstallStrategy, locale: Locale) {
  const labels: Record<Locale, Record<ToolInstallStrategy, string>> = {
    en: {
      auto_download: "auto-download",
      detect_only: "detect-only",
      api_only: "API-only",
      system_installer: "app-managed installer",
      managed_download: "app-managed package",
    },
    vi: {
      auto_download: "tự tải",
      detect_only: "chỉ dò",
      api_only: "chỉ qua API",
      system_installer: "app quản lý",
      managed_download: "app quản lý",
    },
  };
  return labels[locale][strategy] ?? strategy;
}

function toolRiskLabel(risk: ToolRisk, locale: Locale) {
  const labels: Record<Locale, Record<ToolRisk, string>> = {
    en: {
      passive: "passive",
      safe_remote_vantage: "remote",
      active_scanner: "active",
      intrusive_scanner: "intrusive",
    },
    vi: {
      passive: "thụ động",
      safe_remote_vantage: "từ xa",
      active_scanner: "chủ động",
      intrusive_scanner: "xâm nhập",
    },
  };
  return labels[locale][risk] ?? risk;
}

function toolCategoryLabel(category: ToolCategory, locale: Locale) {
  const labels: Record<Locale, Record<ToolCategory, string>> = {
    en: {
      path_diagnostics: "path diagnostics",
      dns: "DNS",
      web: "web",
      port_discovery: "port discovery",
      vuln_scanning: "vulnerability scanning",
      remote_vantage: "điểm đo từ xa",
      local_inspection: "local inspection",
    },
    vi: {
      path_diagnostics: "chẩn đoán đường đi",
      dns: "DNS",
      web: "web",
      port_discovery: "dò port",
      vuln_scanning: "quét lỗ hổng",
      remote_vantage: "remote vantage",
      local_inspection: "kiểm tra local",
    },
  };
  return labels[locale][category] ?? category.replace(/_/g, " ");
}

function capabilityLabel(capability: string, locale: Locale) {
  const labels: Record<Locale, Record<string, string>> = {
    en: {
      port_scan: "port scan",
      template_scan: "template scan",
    },
    vi: {
      port_scan: "quét port",
      template_scan: "quét template",
    },
  };
  return labels[locale][capability] ?? capability.replace(/_/g, " ");
}

function defaultScannerProfile(
  toolId: string,
  interactionCatalog?: InteractionCatalog | null,
): ScannerProfileId {
  return defaultScannerProfileFromCatalog(interactionCatalog, toolId)
    ?? (toolId === "nuclei" ? "safe" : "fast");
}

function scannerIntro(toolId: string, locale: Locale) {
  const vi = locale === "vi";
  switch (toolId) {
    case "nmap":
    case "naabu":
      return vi ? "Quét port có giới hạn trên IP hoặc tên miền đã nhập." : "Run bounded port discovery on the entered host or domain.";
    case "httpx":
      return vi ? "Probe HTTP có giới hạn, status, title và technology." : "Probe HTTP with bounded status, title and technology checks.";
    case "subfinder":
      return vi ? "Tìm subdomain thụ động cho domain đã nhập." : "Discover subdomains passively for the entered domain.";
    case "dnsx":
      return vi ? "Resolve DNS có giới hạn cho một số service name phổ biến." : "Resolve a bounded set of common service names.";
    case "trippy":
      return vi ? "Báo cáo path JSON một chu kỳ, không chạy liên tục." : "Produce one bounded JSON path report, not a continuous stream.";
    case "nexttrace":
      return vi ? "Trace route JSON có giới hạn với hop enrichment." : "Produce a bounded JSON route trace with hop enrichment.";
    case "nuclei":
      return vi ? "Template scan intrusive dùng profile có giới hạn." : "Intrusive template scanning uses bounded profiles.";
    default:
      return vi ? "Chạy tool ngoài trên mục tiêu đã nhập." : "Run an external tool on the entered target.";
  }
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

export function defaultScannerPorts(): ScannerPortsId {
  return "top";
}

function scannerProfileOptions(
  toolId: string,
  locale: Locale,
  interactionCatalog?: InteractionCatalog | null,
): Array<{ id: ScannerProfileId; label: string; description: string }> {
  if (interactionCatalog) {
    return scannerProfileOptionsFromCatalog(interactionCatalog, toolId);
  }

  if (toolId === "nuclei") {
    return [
      {
        id: "safe",
        label: locale === "vi" ? "An toàn" : "Safe",
        description: locale === "vi" ? "misconfig/exposure, bỏ interactsh" : "misconfig/exposure, no interactsh",
      },
      {
        id: "http_exposure",
        label: locale === "vi" ? "Phơi lộ HTTP" : "HTTP exposure",
        description: locale === "vi" ? "template HTTP + phơi lộ" : "HTTP and exposure templates",
      },
      {
        id: "known_vulns",
        label: locale === "vi" ? "CVE/lỗ hổng" : "CVE/vuln",
        description: locale === "vi" ? "CVE, RCE, LFI, SQLi, XSS" : "CVE, RCE, LFI, SQLi, XSS",
      },
      {
        id: "full",
        label: locale === "vi" ? "Toàn bộ đã chọn" : "Full selected",
        description: locale === "vi" ? "mọi severity đã chọn" : "all selected severities",
      },
    ];
  }
  if (toolId !== "nmap") {
    return [
      {
        id: "fast",
        label: locale === "vi" ? "Giới hạn an toàn" : "Bounded default",
        description:
          locale === "vi"
            ? "profile một đích, giới hạn tốc độ và số lần thử"
            : "single-target profile with bounded rates and retries",
      },
    ];
  }
  return [
    {
      id: "fast",
      label: locale === "vi" ? "Nhanh" : "Fast",
      description: locale === "vi" ? "100 TCP port phổ biến" : "top 100 TCP ports",
    },
    {
      id: "version",
      label: locale === "vi" ? "Phiên bản" : "Version",
      description: locale === "vi" ? "phát hiện phiên bản dịch vụ nhẹ" : "light service detection",
    },
    {
      id: "deep",
      label: locale === "vi" ? "Chuyên sâu" : "Deep",
      description: locale === "vi" ? "service + OS/script nhẹ" : "service, OS and light scripts",
    },
    {
      id: "udp_quick",
      label: locale === "vi" ? "UDP nhanh" : "UDP quick",
      description: locale === "vi" ? "25 UDP port phổ biến" : "top 25 UDP ports",
    },
  ];
}

function defaultEnabledLabel(enabled: boolean, locale: Locale) {
  if (enabled) {
    return locale === "vi" ? "Bật" : "enabled";
  }
  return locale === "vi" ? "Tắt" : "disabled";
}

function packageStatusDetailLabel(
  runtime: ToolRuntimeStatus | null,
  lifecycle: ToolLifecyclePlan | null,
  locale: Locale,
) {
  if (runtime?.available) {
    return runtime.version ?? runtime.executable ?? (locale === "vi" ? "đã sẵn sàng" : "available");
  }
  if (locale === "vi") {
    if (runtime?.error) {
      return "Chưa tìm thấy runtime. Kiểm tra cài đặt hoặc bấm cài/cập nhật gói.";
    }
    if (lifecycle?.install_supported) {
      return "Gói có thể cài hoặc cập nhật từ SonarNwork.";
    }
    return "Bấm Dò gói để kiểm tra.";
  }
  return runtime?.error ?? lifecycle?.note ?? "Run package detection.";
}

function toolPageSubtitle(tool: ManagedToolDescriptor, locale: Locale) {
  if (tool.id === "nmap") {
    return locale === "vi"
      ? "Nmap là gói scanner của SonarNwork; app quản lý detect/chạy, installer có thể cần Npcap hoặc quyền hệ thống."
      : "Nmap is a SonarNwork scanner package; the app manages detection/run, while the installer may need Npcap or system permission.";
  }
  if (tool.id === "nuclei") {
    return locale === "vi"
      ? "Nuclei là gói scanner của SonarNwork; app quản lý cài/cập nhật và chạy template theo profile đã chọn."
      : "Nuclei is a SonarNwork scanner package; the app manages install, update, and template runs using the selected profile.";
  }
  return tool.notes;
}

function toolPageDescription(tool: ManagedToolDescriptor, locale: Locale) {
  if (tool.id === "nmap") {
    return locale === "vi"
      ? "SonarNwork dò runtime, chạy scan trong app và mở CLI qua sonarnwork; cập nhật dùng installer chính thức."
      : "SonarNwork detects the runtime, runs scans in-app, and opens the sonarnwork CLI; updates use the official installer.";
  }
  if (tool.id === "nuclei") {
    return locale === "vi"
      ? "SonarNwork tải/cập nhật Nuclei vào thư mục app và chạy template ngay theo profile đã chọn."
      : "SonarNwork installs or updates Nuclei in the app-managed tools folder and runs templates using the selected profile.";
  }
  return tool.notes;
}

function summaryRowValue(result: ProbeRunView | null, label: string) {
  const rows =
    result?.interpretation?.summary_rows && result.interpretation.summary_rows.length > 0
      ? result.interpretation.summary_rows
      : result?.output.summary_rows ?? [];
  return (
    rows
      .find((row) => row.label.toLowerCase() === label.toLowerCase())
      ?.value.trim() || null
  );
}

function isCgnatIp(value: string) {
  const ip = firstIpv4(value);
  if (!ip) {
    return false;
  }
  return ip[0] === 100 && ip[1] >= 64 && ip[1] <= 127;
}

function containsPrivateIp(value: string) {
  const matches = value.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? [];
  return matches.some((item) => {
    const ip = firstIpv4(item);
    if (!ip) {
      return false;
    }
    return (
      ip[0] === 10 ||
      (ip[0] === 172 && ip[1] >= 16 && ip[1] <= 31) ||
      (ip[0] === 192 && ip[1] === 168)
    );
  });
}

function firstIpv4(value: string) {
  const match = value.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/);
  if (!match) {
    return null;
  }

  const octets = match[0].split(".").map(Number);
  return octets.length === 4 && octets.every((octet) => octet >= 0 && octet <= 255)
    ? octets
    : null;
}

function positiveIntegerText(value: string) {
  return value
    .split(/\D+/)
    .some((part) => Number.parseInt(part, 10) > 0);
}

function probesByIds(catalog: ProbeDescriptor[], ids: string[]) {
  const seen = new Set<string>();
  return ids
    .filter((id) => {
      if (seen.has(id)) {
        return false;
      }
      seen.add(id);
      return true;
    })
    .map((id) => catalog.find((probe) => probe.id === id))
    .filter((probe): probe is ProbeDescriptor => Boolean(probe));
}

function hasTauriRuntime() {
  return Boolean(
    (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__,
  );
}

function isTauriRuntimeUnavailable(err: unknown) {
  return !hasTauriRuntime() || String(err).includes("Cannot read properties of undefined");
}

function commandOutputFromRaw(raw: unknown): CommandOutput | null {
  if (!raw || typeof raw !== "object") {
    return null;
  }

  const value = raw as Record<string, unknown>;
  if (
    typeof value.command !== "string" &&
    typeof value.stdout !== "string" &&
    typeof value.stderr !== "string"
  ) {
    return null;
  }

  return {
    command: typeof value.command === "string" ? value.command : "",
    args: Array.isArray(value.args)
      ? value.args.filter((arg): arg is string => typeof arg === "string")
      : [],
    exitCode:
      typeof value.exit_code === "number" || value.exit_code === null
        ? value.exit_code
        : undefined,
    stdout: typeof value.stdout === "string" ? value.stdout : "",
    stderr: typeof value.stderr === "string" ? value.stderr : "",
  };
}

function formatOutputDetail({
  result,
  liveLines,
  selectedProbe,
  commandPreview,
  locale,
}: {
  result: ProbeRunView | null;
  liveLines: string[];
  selectedProbe: ProbeDescriptor | undefined;
  commandPreview: CommandPreview | null;
  locale: Locale;
}) {
  if (result) {
    const commandOutput = commandOutputFromRaw(result.output.raw);
    if (commandOutput) {
      return formatCommandOutput(
        commandOutput,
        commandPreview && selectedProbe
          ? commandPreviewLabel(selectedProbe, commandPreview)
          : compactCommandDisplay(commandOutput.command),
      );
    }

    return formatJsonOutput(result.output.raw ?? result);
  }

  if (liveLines.length > 0) {
    return normalizeTerminalText(liveLines.join("\n"));
  }

  return locale === "vi"
    ? "Kết quả thô sẽ nằm ở đây sau khi chạy."
    : "Raw output will appear here after a run.";
}

function formatCommandOutput(output: CommandOutput, displayCommand?: string) {
  const commandLine =
    displayCommand ??
    [output.command, ...output.args].filter((part) => part.length > 0).join(" ");
  const sections = [
    commandLine ? `$ ${commandLine}` : null,
    `[exit] code ${output.exitCode ?? "unknown"}`,
  ];
  const stdout = normalizeTerminalText(output.stdout).trimEnd();
  const stderr = normalizeTerminalText(output.stderr).trimEnd();

  if (stdout) {
    sections.push("", stdout);
  }
  if (stderr) {
    sections.push("", "[stderr]", stderr);
  }

  return sections.filter((section) => section !== null).join("\n");
}

function formatJsonOutput(value: unknown) {
  return normalizeTerminalText(JSON.stringify(value, null, 2));
}

function normalizeTerminalText(value: string) {
  return value.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

function capturedLiveLines(summary: ProbeLiveSummary) {
  return [
    ...summary.stdout.map((line) => normalizeTerminalText(line)),
    ...summary.stderr.map((line) => `[stderr] ${normalizeTerminalText(line)}`),
    ...(summary.truncated && summary.raw_output_path
      ? [`[output truncated; full log: ${summary.raw_output_path}]`]
      : []),
    `[exit] code ${summary.exit_code ?? "unknown"}`,
  ].filter((line) => line.trim().length > 0);
}


function hasStreamedLivePayload(lines: string[]) {
  return lines.some((line) => {
    const trimmed = line.trim();
    return (
      trimmed.length > 0 &&
      !trimmed.startsWith("$ ") &&
      !trimmed.startsWith("[done]") &&
      !trimmed.startsWith("[exit]") &&
      !trimmed.startsWith("[stop]") &&
      !trimmed.startsWith("[stopped]")
    );
  });
}

function commandPreviewLabel(probe: ProbeDescriptor, preview: CommandPreview) {
  const labels: Record<string, string> = {
    "public.egress_check": "SonarNwork CLI: public egress IP + DNS path",
    "dns.leak_check": "SonarNwork CLI: configured DNS + observed resolver path",
    "public.port_check": "SonarNwork CLI: remote port plan",
    "recon.whois_rdap": "SonarNwork CLI: RDAP lookup",
    "web.http_probe": "SonarNwork CLI: HTTP status, headers, title",
    "web.tls_cert": "SonarNwork CLI: TLS handshake + certificate details",
  };

  return labels[probe.id] ?? preview.display;
}

function compactCommandDisplay(value: string) {
  return truncateLabel(value.replace(/\s+/g, " ").trim(), 120);
}

function clipSummaryValue(value: string) {
  return truncateLabel(value.trim(), 180);
}

function truncateLabel(value: string, maxLength: number) {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, Math.max(0, maxLength - 3))}...`;
}

function formatDnsSummary(
  summary: NetworkSummary | null,
  loading: boolean,
  locale: Locale,
) {
  if (!summary && loading) {
    return locale === "vi" ? "đang kiểm tra" : "checking";
  }

  const observedDns = summary?.observedDns.filter(isUsefulDnsRow) ?? [];
  const configuredDns = summary?.dnsServers.filter(isUsefulDnsRow) ?? [];
  const first = observedDns[0] ?? configuredDns[0];
  if (!first) {
    return summary?.error
      ? locale === "vi"
        ? "không khả dụng"
        : "unavailable"
      : locale === "vi"
        ? "chưa rõ"
        : "unknown";
  }

  const totalDnsRows = observedDns.length + configuredDns.length;
  const suffix = totalDnsRows > 1 ? ` +${totalDnsRows - 1}` : "";
  return `${truncateLabel(first.replace(/\s+/g, " "), 36)}${suffix}`;
}

function formatDnsTitle(summary: NetworkSummary | null, locale: Locale) {
  if (!summary) {
    return locale === "vi" ? "DNS: đang kiểm tra" : "DNS: checking";
  }

  const observedDns = summary.observedDns.filter(isUsefulDnsRow);
  const observedErrors = summary.observedDns.filter((server) => !isUsefulDnsRow(server));
  const configuredDns = summary.dnsServers.filter(isUsefulDnsRow);
  if (observedDns.length === 0 && configuredDns.length === 0) {
    return summary.error
      ? `${locale === "vi" ? "DNS không khả dụng" : "DNS unavailable"}: ${summary.error}`
      : locale === "vi"
        ? "DNS chưa rõ"
        : "DNS unknown";
  }

  return [
    observedDns.length > 0 ? (locale === "vi" ? "Quan sát:" : "Observed:") : "",
    ...observedDns,
    configuredDns.length > 0 ? (locale === "vi" ? "Cấu hình:" : "Configured:") : "",
    ...configuredDns,
    observedErrors.length > 0 ? (locale === "vi" ? "Lỗi quan sát:" : "Observed errors:") : "",
    ...observedErrors,
  ]
    .filter((line) => line.length > 0)
    .join("\n");
}

function isUsefulDnsRow(value: string) {
  const normalized = value.trim().toLowerCase();
  return (
    normalized.length > 0 &&
    !normalized.includes(": error") &&
    !normalized.includes("-> error")
  );
}

function getInitialLocale(): Locale {
  const saved = window.localStorage.getItem("sonarnwork.locale");
  return saved === "en" || saved === "vi" ? saved : "vi";
}

function getInitialTheme(): ThemeMode {
  const saved = window.localStorage.getItem("sonarnwork.theme");
  return saved === "dark" || saved === "light" ? saved : "light";
}
