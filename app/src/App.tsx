import { useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import {
  Activity,
  ChevronDown,
  CircleDot,
  Database,
  Globe2,
  Languages,
  ListChecks,
  Play,
  RefreshCw,
  Search,
  ShieldCheck,
  Square,
  SquareTerminal,
  Terminal,
} from "lucide-react";
import appIcon from "./assets/sonarnwork-icon.png";
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

type ProbeRunView = {
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
  powershell: string;
  cmd: string;
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

type ToolInstallStrategy = "auto_download" | "detect_only" | "api_only";
type ToolRisk = "passive" | "safe_remote_vantage" | "active_scanner" | "intrusive_scanner";
type ToolCategory =
  | "path_diagnostics"
  | "dns"
  | "web"
  | "port_discovery"
  | "vuln_scanning"
  | "remote_vantage"
  | "local_inspection";

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

type ProbeLiveEvent = {
  run_id: string;
  kind: "start" | "stdout" | "stderr" | "exit";
  line?: string | null;
  command?: string | null;
  exit_code?: number | null;
  done: boolean;
};

type ProbeLiveSummary = {
  command: string;
  exit_code?: number | null;
  stdout: string[];
  stderr: string[];
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

type TerminalShell = "powershell" | "cmd";
type ThemeMode = "light" | "dark";

const DEFAULT_WORKFLOW_ID = "internet_path";
const DEFAULT_PROBE_ID = "public.egress_check";

const SUGGESTED_TARGETS = new Set(["", "1.1.1.1", "example.com", "example.com:443"]);
const MANAGED_TOOL_WORKFLOWS = [
  { workflowId: "tool_nmap", toolId: "nmap" },
  { workflowId: "tool_nuclei", toolId: "nuclei" },
] as const;

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
      label: "Local host / LAN",
      eyebrow: "Local host",
      title: "Local network state + listening ports",
      description:
        "Interface, local IP, gateway, DNS resolver, listening socket, route table.",
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
      label: "Local → Internet / target",
      eyebrow: "Local vantage",
      title: "Local check ra Internet / target",
      description:
        "Public IP, DNS, ping, traceroute, HTTP, TLS đều chạy từ local host.",
    },
  },
  public_service: {
    en: {
      label: "Public ingress",
      eyebrow: "Public ingress",
      title: "Listening ports + public port check",
      description:
        "Separate local listener evidence from the planned remote public port check.",
    },
    vi: {
      label: "Public ingress",
      eyebrow: "Public ingress",
      title: "Listening ports + public port check",
      description:
        "Tách local listener evidence khỏi public port check cần remote vantage.",
    },
  },
  tool_nmap: {
    en: {
      label: "Nmap",
      eyebrow: "Managed scanner",
      title: "Nmap",
      description:
        "Port discovery stays in its own tool tab, detect-only by default.",
    },
    vi: {
      label: "Nmap",
      eyebrow: "Managed scanner",
      title: "Nmap",
      description:
        "Port discovery nam o tab rieng, mac dinh chi detect cong cu.",
    },
  },
  tool_nuclei: {
    en: {
      label: "Nuclei",
      eyebrow: "Managed scanner",
      title: "Nuclei",
      description:
        "Template scanning has a separate risk and update policy.",
    },
    vi: {
      label: "Nuclei",
      eyebrow: "Managed scanner",
      title: "Nuclei",
      description:
        "Template scanning co tab rieng, risk va update policy tach khoi Nmap.",
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
      eyebrow: "Public lookup",
      title: "WHOIS / RDAP lookup",
      description: "Tra cuu dang ky cong khai cho domain, IP, URL hoac host:port.",
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
      eyebrow: "Local host",
      title: "Local network state",
      subtitle: "Interface, local IP, gateway, DNS",
    },
  },
  "local.listening_ports": {
    en: {
      eyebrow: "Local listener",
      title: "Listening ports",
      subtitle: "Ports and bind addresses",
    },
    vi: {
      eyebrow: "Local listener",
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
      title: "DNS leak check",
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
      title: "DNS lookup / nslookup",
      subtitle: "A/AAAA/MX/TXT/NS records",
    },
  },
  "connectivity.ping": {
    en: {
      eyebrow: "Local → target",
      title: "Ping",
      subtitle: "Ping + packet loss",
    },
    vi: {
      eyebrow: "Local → target",
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
      eyebrow: "Local → target",
      title: "Traceroute",
      subtitle: "Hop path to target",
    },
  },
  "connectivity.fast_trace": {
    en: {
      eyebrow: "Local → target",
      title: "Fast traceroute",
      subtitle: "Short hop-limited trace",
    },
    vi: {
      eyebrow: "Local → target",
      title: "Fast traceroute",
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
      eyebrow: "Local → target",
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
      eyebrow: "Local → target",
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
      eyebrow: "Local route table",
      title: "Route print",
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
      eyebrow: "Local reachability",
      title: "TCP connect check",
      subtitle: "Local host to host:port",
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
      title: "HTTP probe",
      subtitle: "HTTP status + headers",
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
      title: "TLS certificate",
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
      eyebrow: "Public ingress",
      title: "Public port check",
      subtitle: "Cần remote vantage",
    },
  },
  "recon.whois_rdap": {
    en: {
      eyebrow: "Public lookup",
      title: "WHOIS / RDAP",
      subtitle: "Registrar, dates, nameservers",
    },
    vi: {
      eyebrow: "Public lookup",
      title: "WHOIS / RDAP",
      subtitle: "Registrar, dates, nameservers",
    },
  },
};

const NEXT_ACTION_COPY: Record<string, Record<Locale, string>> = {
  "next_action.check_dns_leak": {
    en: "DNS leak check",
    vi: "DNS leak check",
  },
  "next_action.trace_path": {
    en: "Traceroute",
    vi: "Traceroute",
  },
  "next_action.check_public_port": {
    en: "Public port check",
    vi: "Public port check",
  },
};

const SUMMARY_LABELS: Record<string, Record<Locale, string>> = {
  Type: { en: "Type", vi: "Loại" },
  Entity: { en: "Entity", vi: "Entity" },
  Target: { en: "Target", vi: "Đích" },
  "Resolved IP": { en: "Resolved IP", vi: "IP resolve" },
  Replies: { en: "Replies", vi: "Gói đã gửi" },
  "Packet loss": { en: "Packet loss", vi: "Mất gói" },
  Latency: { en: "Latency", vi: "Độ trễ TB" },
  Hops: { en: "Hops", vi: "Số chặng" },
  "Last hop": { en: "Last hop", vi: "Chặng cuối" },
  Timeouts: { en: "Timeouts", vi: "Timeout" },
  Route: { en: "Route", vi: "Tuyến" },
  Interface: { en: "Interface", vi: "Interface" },
  Gateway: { en: "Gateway", vi: "Gateway" },
  Source: { en: "Source", vi: "Nguồn" },
  "Public IP": { en: "Public IP", vi: "IP công khai" },
  "DNS servers": { en: "DNS servers", vi: "DNS cấu hình" },
  "Observed DNS": { en: "Observed DNS", vi: "DNS quan sát" },
  Errors: { en: "Errors", vi: "Lỗi" },
  "Local IPs": { en: "Local IPs", vi: "IP local" },
  Listeners: { en: "Listeners", vi: "Port listen" },
  "Public binds": { en: "Public binds", vi: "Bind mọi interface" },
  Server: { en: "Server", vi: "Server" },
  Address: { en: "Address", vi: "Địa chỉ" },
  Records: { en: "Records", vi: "Bản ghi" },
  "HTTP status": { en: "HTTP status", vi: "HTTP status" },
  "Final URL": { en: "Final URL", vi: "URL cuối" },
  "Content-Type": { en: "Content-Type", vi: "Content-Type" },
  Title: { en: "Title", vi: "Title" },
  Security: { en: "Security", vi: "Security" },
  Protocol: { en: "Protocol", vi: "Protocol" },
  Subject: { en: "Subject", vi: "Subject" },
  Issuer: { en: "Issuer", vi: "Issuer" },
  Expires: { en: "Expires", vi: "Hết hạn" },
  Handle: { en: "Handle", vi: "Handle" },
  Country: { en: "Country", vi: "Quốc gia" },
  Nameservers: { en: "Nameservers", vi: "Nameserver" },
  Entities: { en: "Entities", vi: "Entity" },
  Connected: { en: "Connected", vi: "Kết nối" },
  Remote: { en: "Remote", vi: "Remote" },
  Elapsed: { en: "Elapsed", vi: "Thời gian" },
  Exit: { en: "Exit", vi: "Exit" },
  Lines: { en: "Lines", vi: "Dòng" },
};

export default function App() {
  const [locale, setLocale] = useState<Locale>(getInitialLocale);
  const [theme, setTheme] = useState<ThemeMode>(getInitialTheme);
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [target, setTarget] = useState("1.1.1.1");
  const [entity, setEntity] = useState<EntityValue | null>(null);
  const [catalog, setCatalog] = useState<ProbeDescriptor[]>([]);
  const [workflows, setWorkflows] = useState<WorkflowDescriptor[]>([]);
  const [managedTools, setManagedTools] = useState<ManagedToolDescriptor[]>([]);
  const [availableProbes, setAvailableProbes] = useState<ProbeDescriptor[]>([]);
  const [networkSummary, setNetworkSummary] = useState<NetworkSummary | null>(null);
  const [remotePlan, setRemotePlan] = useState<RemoteVantagePlan | null>(null);
  const [remotePlanError, setRemotePlanError] = useState<string | null>(null);
  const [activeWorkflowId, setActiveWorkflowId] = useState(DEFAULT_WORKFLOW_ID);
  const [selectedProbeId, setSelectedProbeId] = useState(DEFAULT_PROBE_ID);
  const [result, setResult] = useState<ProbeRunView | null>(null);
  const [commandPreview, setCommandPreview] = useState<CommandPreview | null>(null);
  const [commandText, setCommandText] = useState("");
  const [commandDirty, setCommandDirty] = useState(false);
  const [targetPort, setTargetPort] = useState("");
  const [liveLines, setLiveLines] = useState<string[]>([]);
  const [terminalShell, setTerminalShell] = useState<TerminalShell>("powershell");
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

  const workflowList = useMemo(
    () => uiWorkflows(workflows.length > 0 ? workflows : fallbackWorkflows(), catalog),
    [catalog, workflows],
  );
  const activeWorkflow =
    workflowList.find((workflow) => workflow.id === activeWorkflowId) ?? workflowList[0];
  const activeWorkflowCopy = workflowCopy(activeWorkflow?.id, locale);
  const activeToolId = toolIdForWorkflow(activeWorkflow?.id);
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
        const [nextInfo, nextCatalog, nextWorkflows, nextTools] = await Promise.all([
          invoke<AppInfo>("app_info"),
          invoke<ProbeDescriptor[]>("all_probes"),
          invoke<WorkflowDescriptor[]>("workflows"),
          invoke<{ tools: ManagedToolDescriptor[] }>("tools_catalog"),
        ]);
        setInfo(nextInfo);
        setCatalog(nextCatalog);
        setWorkflows(nextWorkflows);
        setManagedTools(nextTools.tools);
        applyInitialSelection(nextWorkflows, nextCatalog);
      } catch (err) {
        if (isTauriRuntimeUnavailable(err)) {
          const nextCatalog = fallbackCatalog();
          const nextWorkflows = fallbackWorkflows();
          setInfo(fallbackAppInfo());
          setCatalog(nextCatalog);
          setWorkflows(nextWorkflows);
          setManagedTools(fallbackManagedTools());
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

    async function bindLiveOutput() {
      if (!hasTauriRuntime()) {
        return;
      }

      unlisten = await listen<ProbeLiveEvent>("probe-live-output", (event) => {
        const payload = event.payload;
        if (payload.run_id !== liveRunIdRef.current) {
          return;
        }

        if (payload.kind === "start" && payload.command) {
          setLiveLines((lines) =>
            lines.length > 0 ? lines : [`$ ${compactCommandDisplay(payload.command ?? "")}`],
          );
          return;
        }

        if ((payload.kind === "stdout" || payload.kind === "stderr") && payload.line) {
          setLiveLines((lines) => [
            ...lines,
            payload.kind === "stderr" ? `[stderr] ${payload.line}` : payload.line ?? "",
          ]);
          return;
        }

        if (payload.kind === "exit") {
          setLiveLines((lines) => [
            ...lines,
            `\n[exit] code ${payload.exit_code ?? "unknown"}`,
          ]);
        }
      });

      if (disposed && unlisten) {
        unlisten();
      }
    }

    void bindLiveOutput();

    return () => {
      disposed = true;
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
      const response = await invoke<ProbeRunView>("run_probe", {
        probeId: selectedProbe.id,
        target: probeTarget(selectedProbe, target, targetPort),
      });
      setResult(response);
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
      setLiveLines((lines) => [
        ...lines,
        ...(hasStreamedLivePayload(lines) ? [] : capturedLiveLines(summary)),
        wasStopped
          ? `\n[stopped] ${summary.command} stopped with ${summary.exit_code ?? "unknown"}; partial output kept`
          : `\n[done] ${summary.command} exited with ${summary.exit_code ?? "unknown"}`,
      ]);
    } catch (err) {
      setError(String(err));
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
        shell: terminalShell,
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

  return (
    <main
      className="shell"
      data-theme={theme}
      data-workflow={activeWorkflow?.id ?? DEFAULT_WORKFLOW_ID}
    >
      <section className="appWindow">
        <header className="appTopbar">
          <div className="brandMark">
            <span className="brandIcon">
              <img src={appIcon} alt="" />
            </span>
            <strong>{info?.name ?? "SonarNwork"}</strong>
          </div>

          <nav className="topTabs" aria-label="SonarNwork workflows">
            {workflowList.map((workflow) => (
              <button
                className={workflow.id === activeWorkflow?.id ? "active" : ""}
                key={workflow.id}
                onClick={() => selectWorkflow(workflow)}
              >
                {workflowCopy(workflow.id, locale).label}
              </button>
            ))}
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

        <section className="workspace">
          <header className="questionHeader">
            <p>{activeWorkflowCopy.eyebrow}</p>
            <h1>{activeWorkflowCopy.title}</h1>
            <span>{activeWorkflowCopy.description}</span>
          </header>

          {activeToolId ? (
            <ManagedToolPage
              locale={locale}
              tool={activeManagedTool}
              toolId={activeToolId}
            />
          ) : (
            <>
          <section className="checkGrid" aria-label="Recommended checks">
            {workflowTools.map((probe) => (
              <CheckCard
                key={probe.id}
                probe={probe}
                locale={locale}
                active={probe.id === selectedProbe?.id}
                workflowId={activeWorkflow?.id}
                disabled={probeRequiresRemoteVantage(probe.id)}
                onSelect={() => selectProbe(probe)}
              />
            ))}
          </section>

          {error ? <p className="errorBanner">{error}</p> : null}

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
                    <span>Port</span>
                    <input
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
                        <span>{locale === "vi" ? "Live output" : "Live output"}</span>
                      </button>
                      <button
                        className="secondaryButton"
                        disabled={!selectedRunnable}
                        onClick={() => void openTerminalForProbe()}
                      >
                        <Terminal size={15} />
                        <span>{locale === "vi" ? "Mở terminal" : "Terminal"}</span>
                      </button>
                      <div className="segmented">
                        <button
                          className={terminalShell === "powershell" ? "active" : ""}
                          onClick={() => setTerminalShell("powershell")}
                        >
                          PS
                        </button>
                        <button
                          className={terminalShell === "cmd" ? "active" : ""}
                          onClick={() => setTerminalShell("cmd")}
                        >
                          CMD
                        </button>
                      </div>
                    </div>
                    <label className="commandEditor">
                      <SquareTerminal size={14} />
                      <textarea
                        value={commandText}
                        spellCheck={false}
                        aria-label="Command preview"
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

          {activeWorkflow?.id === "public_service" ? (
            <>
              {selectedRequiresRemote ? (
                <RemotePlanPanel
                  locale={locale}
                  plan={remotePlan}
                  loading={isRemotePlanLoading}
                  error={remotePlanError}
                />
              ) : (
                <PublicServicePlan
                  locale={locale}
                  networkSummary={networkSummary}
                  result={result}
                  onSelectProbe={selectProbeId}
                />
              )}
            </>
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
              <p className="emptyResult">
                {selectedRequiresRemote
                  ? locale === "vi"
                    ? "Phần nhìn từ internet cần remote vantage/token, chưa chạy bằng lệnh local."
                    : "Outside visibility needs a remote vantage/token and is not faked locally."
                  : locale === "vi"
                    ? "Chạy check để xem verdict và summary rows."
                    : "Run a check to see the answer here."}
              </p>
            )}

            {result?.output.warnings && result.output.warnings.length > 0 ? (
              <div className="warningStrip">
                {result.output.warnings.map((warning, index) => (
                  <span key={`${warning.code ?? "warning"}-${index}`}>
                    {warning.message ?? warning.code ?? "Warning"}
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

            </>
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
      className={`checkCard direction-${directionClass(probe.id)} ${
        active ? "active" : ""
      } ${compact ? "compact" : ""} ${
        disabled ? "planned" : ""
      }`}
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
          ? "Public ingress readiness"
          : "Public ingress readiness"}
      </strong>
      <p>
        {locale === "vi"
          ? "May local co the thu thap bang chung, con buoc ket luan Internet -> service can remote vantage that."
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

function ManagedToolPage({
  locale,
  tool,
  toolId,
}: {
  locale: Locale;
  tool: ManagedToolDescriptor | undefined;
  toolId: string;
}) {
  const effectiveTool = tool ?? managedToolForId([], toolId);
  const [updatePlan, setUpdatePlan] = useState<ToolUpdatePlan | null>(null);
  const [updateError, setUpdateError] = useState<string | null>(null);

  useEffect(() => {
    setUpdatePlan(null);
    setUpdateError(null);
  }, [toolId]);

  if (!effectiveTool) {
    return (
      <section className="externalScannerPanel managedToolPage">
        <header>
          <div>
            <strong>{toolId}</strong>
            <span>
              {locale === "vi"
                ? "Chua co metadata cho tool nay."
                : "No metadata is available for this tool yet."}
            </span>
          </div>
        </header>
      </section>
    );
  }

  const currentTool = effectiveTool;

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

  return (
    <section className="externalScannerPanel managedToolPage">
      <header>
        <div>
          <strong>
            {locale === "vi"
              ? `${currentTool.display_name} rieng`
              : `${currentTool.display_name} tool`}
          </strong>
          <span>{toolPageSubtitle(currentTool, locale)}</span>
        </div>
      </header>

      <div className="externalToolGrid single">
        <article className={`externalToolCard ${currentTool.id}`}>
          <header>
            <div>
              <small>{toolCategoryLabel(currentTool.category)}</small>
              <strong>{currentTool.display_name}</strong>
            </div>
            <em className={currentTool.risk}>{toolRiskLabel(currentTool.risk)}</em>
          </header>
          <p>{currentTool.notes}</p>
          <dl>
            <div>
              <dt>{locale === "vi" ? "Nguon" : "Source"}</dt>
              <dd>{currentTool.update.source_label}</dd>
            </div>
            <div>
              <dt>{locale === "vi" ? "Cai dat" : "Install"}</dt>
              <dd>{installStrategyLabel(currentTool.install_strategy)}</dd>
            </div>
            <div>
              <dt>{locale === "vi" ? "Mac dinh" : "Default"}</dt>
              <dd>{currentTool.default_enabled ? "enabled" : "disabled"}</dd>
            </div>
          </dl>
          <div className="toolCapabilityRow">
            {currentTool.capabilities.map((capability) => (
              <span key={capability}>{capabilityLabel(capability)}</span>
            ))}
          </div>
          <div className="toolActions">
            <button className="secondaryButton" onClick={() => void requestUpdatePlan()}>
              <RefreshCw size={14} />
              <span>{locale === "vi" ? "Update" : "Update"}</span>
            </button>
            <span>
              {currentTool.update.update_supported ? "GitHub/latest" : "detect-only"}
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
        </article>
      </div>
    </section>
  );
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
        [locale === "vi" ? "Provider" : "Provider", remoteProviderLabel(plan.request.provider)],
        [
          locale === "vi" ? "Phep do" : "Measurement",
          remoteMeasurementLabel(plan.request.measurement),
        ],
        [locale === "vi" ? "Dich" : "Target", formatProbeTarget(plan.request.target)],
        [
          locale === "vi" ? "Scope token" : "Scope token",
          plan.request.scope_token ?? (locale === "vi" ? "cho token handoff" : "pending handoff"),
        ],
      ]
    : [];

  return (
    <section className="plannedPanel remotePlanPanel">
      <strong>
        {locale === "vi"
          ? "Ke hoach remote-scan cho public ingress"
          : "Remote-scan plan for public ingress"}
      </strong>
      <p>
        {locale === "vi"
          ? "Local host khong tu chung minh duoc Internet co connect nguoc vao service. Plan nay chuan bi scope de remote vantage thuc hien buoc do."
          : "Local host cannot prove inbound reachability by itself. This plan prepares the scoped handoff for an outside vantage."}
      </p>

      {loading ? (
        <div className="remotePlanStatus">
          {locale === "vi" ? "Dang tao ke hoach..." : "Preparing plan..."}
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
                <em>{locale === "vi" ? "remote" : "remote"}</em>
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
  const remoteAction = locale === "vi" ? "Lap plan" : "Plan";
  const localStateAction = locale === "vi" ? "Kiem tra LAN" : "Check LAN";
  const listenersAction = locale === "vi" ? "Kiem tra port" : "Check ports";
  const reachabilityAction = locale === "vi" ? "Thu TCP" : "Test TCP";
  const egressIp = networkSummary?.egressIp?.trim() ?? "";
  const localIps = summaryRowValue(result, "Local IPs");
  const publicBinds = summaryRowValue(result, "Public binds");
  const connected = summaryRowValue(result, "Connected");

  return [
    {
      id: "remote-vantage",
      title:
        locale === "vi"
          ? "Remote vantage cho public ingress"
          : "Remote vantage for public ingress",
      detail:
        locale === "vi"
          ? "Sinh handoff de may ben ngoai thu ket noi vao host:port nay."
          : "Prepare a handoff so an outside host can test this host:port.",
      status: locale === "vi" ? "san sang" : "ready",
      tone: "ready",
      actionLabel: remoteAction,
      actionProbeId: "public.port_check",
    },
    natReadinessItem(locale, egressIp, localIps, localStateAction),
    {
      id: "upnp",
      title: locale === "vi" ? "Trang thai UPnP" : "UPnP state",
      detail:
        locale === "vi"
          ? "Chua co probe UPnP local; can bo sung discovery IGD/PCP/NAT-PMP."
          : "No local UPnP probe yet; needs IGD/PCP/NAT-PMP discovery.",
      status: locale === "vi" ? "ke tiep" : "next",
      tone: "planned",
    },
    firewallReadinessItem(locale, publicBinds, connected, listenersAction, reachabilityAction),
    {
      id: "scope-token",
      title:
        locale === "vi"
          ? "Token handoff co pham vi"
          : "Scoped token handoff",
      detail:
        locale === "vi"
          ? "Remote-scan chi duoc tao sau khi chon target va port ro rang."
          : "Remote-scan is prepared only after an explicit host and port are selected.",
      status: locale === "vi" ? "can target" : "needs target",
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
      title: locale === "vi" ? "Goi y NAT / CGNAT" : "NAT / CGNAT hint",
      detail:
        locale === "vi"
          ? `Egress ${egressIp} nam trong 100.64.0.0/10; public ingress co the bi CGNAT chan.`
          : `Egress ${egressIp} is inside 100.64.0.0/10; public ingress may be blocked by CGNAT.`,
      status: locale === "vi" ? "canh bao" : "warning",
      tone: "warning",
      actionLabel,
      actionProbeId: "local.network_state",
    };
  }

  if (egressIp && localIps && containsPrivateIp(localIps)) {
    return {
      id: "nat-cgnat",
      title: locale === "vi" ? "Goi y NAT / CGNAT" : "NAT / CGNAT hint",
      detail:
        locale === "vi"
          ? `May co IP private, egress la ${egressIp}; can port-forward/router rule de mo ingress.`
          : `This host has a private IP and egresses as ${egressIp}; inbound needs a router or port-forward rule.`,
      status: locale === "vi" ? "co NAT" : "NAT likely",
      tone: "warning",
      actionLabel,
      actionProbeId: "local.network_state",
    };
  }

  if (egressIp) {
    return {
      id: "nat-cgnat",
      title: locale === "vi" ? "Goi y NAT / CGNAT" : "NAT / CGNAT hint",
      detail:
        locale === "vi"
          ? `Da thay public egress ${egressIp}; chay LAN check de so voi IP local.`
          : `Public egress ${egressIp} is visible; run LAN check to compare it with local addresses.`,
      status: locale === "vi" ? "mot phan" : "partial",
      tone: "waiting",
      actionLabel,
      actionProbeId: "local.network_state",
    };
  }

  return {
    id: "nat-cgnat",
    title: locale === "vi" ? "Goi y NAT / CGNAT" : "NAT / CGNAT hint",
    detail:
      locale === "vi"
        ? "Can IP egress va IP local de phan biet direct, NAT, hay CGNAT."
        : "Needs egress and local IP evidence to separate direct, NAT, and CGNAT cases.",
    status: locale === "vi" ? "cho du lieu" : "waiting",
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
          ? "Goi y allow/deny cua tuong lua"
          : "Firewall allow/deny hint",
      detail:
        locale === "vi"
          ? "TCP local connect thanh cong; neu remote fail thi xem router/firewall/WAN rule."
          : "Local TCP connect succeeds; if remote fails, inspect router, firewall, or WAN rules.",
      status: locale === "vi" ? "local ok" : "local ok",
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
          ? "Goi y allow/deny cua tuong lua"
          : "Firewall allow/deny hint",
      detail:
        locale === "vi"
          ? "TCP local connect fail; sua service/firewall local truoc khi thu remote."
          : "Local TCP connect fails; fix the service or local firewall before remote testing.",
      status: locale === "vi" ? "chan local" : "local blocked",
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
          ? "Goi y allow/deny cua tuong lua"
          : "Firewall allow/deny hint",
      detail:
        locale === "vi"
          ? `${publicBinds} listener bind moi interface; can TCP check va remote vantage de ket luan.`
          : `${publicBinds} listener(s) bind all interfaces; use TCP check and remote vantage to finish the verdict.`,
      status: locale === "vi" ? "co listener" : "listener found",
      tone: "ready",
      actionLabel: reachabilityAction,
      actionProbeId: "connectivity.reachability",
    };
  }

  return {
    id: "firewall",
    title:
      locale === "vi"
        ? "Goi y allow/deny cua tuong lua"
        : "Firewall allow/deny hint",
    detail:
      locale === "vi"
        ? "Chay listening ports de biet service co bind dung interface khong."
        : "Run listening ports to see whether the service binds the right interface.",
    status: locale === "vi" ? "cho du lieu" : "waiting",
    tone: "waiting",
    actionLabel: listenersAction,
    actionProbeId: "local.listening_ports",
  };
}

function uiWorkflows(
  coreWorkflows: WorkflowDescriptor[],
  catalog: ProbeDescriptor[],
): WorkflowDescriptor[] {
  const workflows = coreWorkflows.filter((workflow) => workflow.id !== "slow_network");
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
  return tools.find((tool) => tool.id === toolId) ??
    fallbackManagedTools().find((tool) => tool.id === toolId);
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
    public_service: ["local.listening_ports"],
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
    return "example.com:443";
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
    "local.listening_ports": {
      en: {
        eyebrow: "Step 1 · Local evidence",
        title: "Listening ports",
        subtitle: "Port/bind on local host",
      },
      vi: {
        eyebrow: "Bước 1 · Local evidence",
        title: "Listening ports",
        subtitle: "Port/bind tại local host",
      },
    },
    "connectivity.reachability": {
      en: {
        eyebrow: "Step 2 · Local reachability",
        title: "TCP connect check",
        subtitle: "TCP from local vantage",
      },
      vi: {
        eyebrow: "Bước 2 · Local reachability",
        title: "TCP connect check",
        subtitle: "TCP từ local vantage",
      },
    },
    "public.port_check": {
      en: {
        eyebrow: "Step 3 · Public ingress",
        title: "Public port check",
        subtitle: "Requires remote vantage",
      },
      vi: {
        eyebrow: "Bước 3 · Public ingress",
        title: "Public port check",
        subtitle: "Cần remote vantage",
      },
    },
  };

  return publicServiceCopy[probeId]?.[locale] ?? null;
}

function directionLabel(probeId: string, locale: Locale) {
  if (probeId.startsWith("local.")) {
    return locale === "vi" ? "local host" : "local host";
  }
  if (probeId === "connectivity.route_check") {
    return locale === "vi" ? "local route table" : "local route table";
  }
  if (probeId === "public.egress_check" || probeId === "dns.leak_check") {
    return locale === "vi" ? "local → internet" : "local → internet";
  }
  if (probeId === "public.port_check") {
    return locale === "vi" ? "public ingress" : "public ingress";
  }
  if (probeId.startsWith("recon.")) {
    return locale === "vi" ? "public records" : "public records";
  }
  if (probeId === "connectivity.reachability") {
    return locale === "vi" ? "local reachability" : "local reachability";
  }
  if (probeId === "dns.lookup") {
    return locale === "vi" ? "local → dns" : "local → DNS";
  }
  if (probeId.startsWith("web.http")) {
    return locale === "vi" ? "local → http" : "local → HTTP";
  }
  if (probeId.startsWith("web.tls")) {
    return locale === "vi" ? "local → tls" : "local → TLS";
  }
  return locale === "vi" ? "local → target" : "local → target";
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
    probeId === "connectivity.reachability" ||
    probeId === "connectivity.route_check"
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

function resultVerdict(
  result: ProbeRunView | null,
  liveLines: string[],
  isLiveRunning: boolean,
  liveWasStopped: boolean,
  selectedProbe: ProbeDescriptor | undefined,
  locale: Locale,
): ResultVerdict {
  if (result?.interpretation?.verdict) {
    return result.interpretation.verdict;
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
  if (liveLines.length > 0 || isLiveRunning) {
    return {
      status: isLiveRunning ? "unknown" : "ok",
      title: isLiveRunning
        ? locale === "vi"
          ? "Lệnh live đang chạy."
          : "Live command is running."
        : locale === "vi"
          ? "Lệnh live đã hoàn tất."
          : "Live command completed.",
      detail: null,
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
        "local.listening_ports",
        "connectivity.reachability",
        "public.port_check",
      ],
      advanced_probe_ids: ["local.network_state"],
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
    warning: "Remote-scan execution requires token handoff and explicit target scope.",
  };
}

function fallbackManagedTools(): ManagedToolDescriptor[] {
  return [
    {
      id: "nuclei",
      display_name: "nuclei",
      source: "project_discovery",
      install_strategy: "auto_download",
      risk: "intrusive_scanner",
      category: "vuln_scanning",
      capabilities: ["template_scan"],
      default_enabled: false,
      notes: "Template scanning is never beginner-default and requires explicit scope.",
      update: {
        source_label: "GitHub: projectdiscovery/nuclei",
        source_url: "https://github.com/projectdiscovery/nuclei",
        latest_url: "https://github.com/projectdiscovery/nuclei/releases/latest",
        update_supported: true,
        update_note:
          "Update from ProjectDiscovery GitHub releases; running templates still requires explicit scope.",
      },
    },
    {
      id: "nmap",
      display_name: "nmap",
      source: "nmap_org",
      install_strategy: "detect_only",
      risk: "active_scanner",
      category: "port_discovery",
      capabilities: ["port_scan"],
      default_enabled: false,
      notes: "Detect-only integration; SonarNwork does not bundle Nmap.",
      update: {
        source_label: "Nmap.org",
        source_url: "https://nmap.org/download.html",
        latest_url: "https://nmap.org/download.html",
        update_supported: false,
        update_note:
          "Detect-only: install or update Nmap with the system installer/package manager, then refresh detection in SonarNwork.",
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

function installStrategyLabel(strategy: ToolInstallStrategy) {
  const labels: Record<ToolInstallStrategy, string> = {
    auto_download: "auto-download",
    detect_only: "detect-only",
    api_only: "API-only",
  };
  return labels[strategy] ?? strategy;
}

function toolRiskLabel(risk: ToolRisk) {
  const labels: Record<ToolRisk, string> = {
    passive: "passive",
    safe_remote_vantage: "remote",
    active_scanner: "active",
    intrusive_scanner: "intrusive",
  };
  return labels[risk] ?? risk;
}

function toolCategoryLabel(category: ToolCategory) {
  return category.replace(/_/g, " ");
}

function capabilityLabel(capability: string) {
  return capability.replace(/_/g, " ");
}

function toolPageSubtitle(tool: ManagedToolDescriptor, locale: Locale) {
  if (tool.id === "nmap") {
    return locale === "vi"
      ? "Nmap chi detect/install ngoai, khong auto-download de tranh goi scanner active vao app."
      : "Nmap is detect-only; SonarNwork does not auto-download an active port scanner.";
  }
  if (tool.id === "nuclei") {
    return locale === "vi"
      ? "Nuclei lay update tu ProjectDiscovery GitHub, nhung scan template van can scope ro rang."
      : "Nuclei updates come from ProjectDiscovery GitHub; template runs still need explicit scope.";
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
    "public.egress_check": "PowerShell: public egress IP + DNS path",
    "dns.leak_check": "PowerShell: configured DNS + observed resolver path",
    "public.port_check": "PowerShell: remote port plan",
    "recon.whois_rdap": "PowerShell: RDAP lookup",
    "web.http_probe": "PowerShell: HTTP status, headers, title",
    "web.tls_cert": "PowerShell: TLS handshake + certificate details",
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
