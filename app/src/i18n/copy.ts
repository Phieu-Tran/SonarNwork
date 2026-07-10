import type {
  Locale,
  ProbeDescriptor,
  ProbeStatus,
  ToolGroupId,
} from "../product";

export const UI_COPY = {
  en: {
    loadingCore: "Loading core",
    probes: "probes",
    sharedCore: "shared core",
    language: "Language",
    refreshNetwork: "Refresh IP and DNS",
    toolGroups: "Tool groups",
    tools: "tools",
    ready: "ready",
    localMachine: "this machine",
    targetNeeded: "needs target",
    noMatch: "no match",
    targetRequired: "target required",
    targetApplies: "target applies",
    notApplicable: "not applicable",
    inspectOnRun: "checked on run",
    chooseTool: "Choose a check.",
    target: "Target",
    targetPlaceholder: "IP, domain, URL, or host:port",
    machineScope: "This check runs on the current machine. No target needed.",
    planned: "Planned",
    runTool: "Run",
    enterTarget: "Enter target",
    runLive: "Live output",
    openTerminal: "Terminal",
    terminalShell: "Terminal shell",
    runSelectedTool: "Run selected check",
    toolUnavailable: "Check unavailable",
    runLiveTitle: "Run and stream output in SonarNwork",
    remoteRequired: "remote-scan required",
    targetEntity: "Target",
    output: "Output",
    noTargetInspected: "No target inspected.",
    localEntity: "Current machine / current internet path",
    liveRunning: "Live command is running.",
    liveOutput: "Live command output.",
    chooseRunOutput: "Pick a check, enter a target if needed, then run.",
    plannedLater: "is planned for a later backend phase.",
    noRunOutput: "No output yet.",
    targetHint: "Targets can be an IP, domain, URL, or host:port.",
    runToSeeOutput: "Run this check to see output here.",
    doesNotApply: "does not apply to this target.",
    internetIp: "Internet IP",
    checking: "checking",
    unknown: "unknown",
    unavailable: "unavailable",
    dnsChecking: "DNS: checking",
    dnsUnavailable: "DNS unavailable",
    dnsUnknown: "DNS unknown",
    observed: "Observed:",
    configured: "Configured:",
    observedErrors: "Observed errors:",
    resultSummary: "Result",
    status: "Status",
    tool: "Check",
    mode: "Mode",
    command: "Command",
    exitCode: "Exit code",
    findings: "Findings",
    warnings: "Warnings",
    lines: "Lines",
    idle: "Idle",
    running: "Running",
    completed: "Completed",
    readyState: "Ready",
    noResultSummary: "Run a check to see the summary.",
    workflows: "Checks",
    primaryChecks: "Main checks",
    advancedTools: "More checks in this direction",
    advancedToolsHint: "Deeper probes that use the same observation direction.",
    workflowToolCount: "quick checks",
    moreActions: "More run options",
    commandPreview: "Command preview",
  },
  vi: {
    loadingCore: "Dang tai core",
    probes: "probe",
    sharedCore: "dung chung core",
    language: "Ngon ngu",
    refreshNetwork: "Cap nhat IP va DNS",
    toolGroups: "Nhom cong cu",
    tools: "cong cu",
    ready: "san sang",
    localMachine: "may hien tai",
    targetNeeded: "can target",
    noMatch: "khong khop",
    targetRequired: "can target",
    targetApplies: "target hop le",
    notApplicable: "khong ap dung",
    inspectOnRun: "kiem tra khi chay",
    chooseTool: "Chon mot kiem tra.",
    target: "Target",
    targetPlaceholder: "IP, domain, URL, hoac host:port",
    machineScope: "Kiem tra tren may hien tai. Khong can target.",
    planned: "Da len ke hoach",
    runTool: "Chay",
    enterTarget: "Nhap target",
    runLive: "Output live",
    openTerminal: "Terminal",
    terminalShell: "Terminal",
    runSelectedTool: "Chay kiem tra dang chon",
    toolUnavailable: "Kiem tra chua kha dung",
    runLiveTitle: "Chay va stream output trong SonarNwork",
    remoteRequired: "can remote-scan",
    targetEntity: "Target",
    output: "Output",
    noTargetInspected: "Chua inspect target.",
    localEntity: "May hien tai / duong internet hien tai",
    liveRunning: "Lenh live dang chay.",
    liveOutput: "Output lenh live.",
    chooseRunOutput: "Chon kiem tra, nhap target neu can, roi chay.",
    plannedLater: "nam o phase backend sau.",
    noRunOutput: "Chua co output.",
    targetHint: "Target co the la IP, domain, URL, hoac host:port.",
    runToSeeOutput: "Chay kiem tra nay de xem output.",
    doesNotApply: "khong ap dung cho target nay.",
    internetIp: "IP internet",
    checking: "dang kiem tra",
    unknown: "chua ro",
    unavailable: "khong kha dung",
    dnsChecking: "DNS: dang kiem tra",
    dnsUnavailable: "DNS khong kha dung",
    dnsUnknown: "DNS chua ro",
    observed: "Quan sat:",
    configured: "Cau hinh:",
    observedErrors: "Loi quan sat:",
    resultSummary: "Ket qua",
    status: "Trang thai",
    tool: "Kiem tra",
    mode: "Che do",
    command: "Lenh",
    exitCode: "Exit code",
    findings: "Finding",
    warnings: "Canh bao",
    lines: "Dong",
    idle: "Chua chay",
    running: "Dang chay",
    completed: "Hoan tat",
    readyState: "San sang",
    noResultSummary: "Chay mot kiem tra de xem tom tat.",
    workflows: "Kiem tra",
    primaryChecks: "Kiem tra chinh",
    advancedTools: "Kiem tra sau hon cung huong",
    advancedToolsHint: "Probe sau hon nhung van cung huong quan sat.",
    workflowToolCount: "kiem tra nhanh",
    moreActions: "Tuy chon chay khac",
    commandPreview: "Lenh se chay",
  },
} as const;

export const STATUS_COPY: Record<Locale, Record<ProbeStatus, string>> = {
  en: {
    ready: "Ready",
    planned: "Planned",
    disabled: "Disabled",
  },
  vi: {
    ready: "San sang",
    planned: "Ke hoach",
    disabled: "Tat",
  },
};

export const RISK_COPY: Record<Locale, Record<string, string>> = {
  en: {
    passive: "passive",
    safe_active: "safe active",
    intrusive: "intrusive",
    dangerous: "dangerous",
  },
  vi: {
    passive: "thu dong",
    safe_active: "active nhe",
    intrusive: "xam lan",
    dangerous: "nguy hiem",
  },
};

export const GROUP_COPY: Record<
  ToolGroupId,
  Record<Locale, { title: string; description: string }>
> = {
  local_machine: {
    en: {
      title: "Local machine",
      description: "Checks from this computer and local resolver/network.",
    },
    vi: {
      title: "May local",
      description: "Kiem tra tren may nay va mang/resolver local.",
    },
  },
  internet_path: {
    en: {
      title: "Internet path",
      description: "Public egress IP and observed DNS path.",
    },
    vi: {
      title: "Duong internet",
      description: "IP public va duong DNS dang di ra internet.",
    },
  },
  public_remote: {
    en: {
      title: "Public remote",
      description: "Checks from an outside vantage point.",
    },
    vi: {
      title: "Public remote",
      description: "Kiem tra tu diem nhin ben ngoai.",
    },
  },
  web_tls: {
    en: {
      title: "Web / TLS",
      description: "Website and certificate checks.",
    },
    vi: {
      title: "Web / TLS",
      description: "Kiem tra website va chung chi.",
    },
  },
  recon: {
    en: {
      title: "Recon / Intel",
      description: "Public ownership and registration lookups.",
    },
    vi: {
      title: "Tra cuu / Intel",
      description: "Tra cuu ownership va dang ky public.",
    },
  },
  core: {
    en: {
      title: "Core",
      description: "Entity and internal contract checks.",
    },
    vi: {
      title: "Core",
      description: "Kiem tra entity va contract noi bo.",
    },
  },
};

export const WORKFLOW_COPY: Record<
  string,
  Record<Locale, { title: string; description: string }>
> = {
  local_network: {
    en: {
      title: "1. Local machine and LAN",
      description: "Interfaces, gateway, DNS, listening ports, and local exposure.",
    },
    vi: {
      title: "1. May local va LAN",
      description: "Interface, gateway, DNS, port dang listen va exposure local.",
    },
  },
  internet_path: {
    en: {
      title: "2. This machine -> Internet / target",
      description:
        "Public IP, DNS path, ping, trace, HTTP, and TLS from this machine outward.",
    },
    vi: {
      title: "2. May nay -> Internet / target",
      description:
        "IP public, duong DNS, ping, trace, HTTP va TLS tu may nay di ra ngoai.",
    },
  },
  slow_network: {
    en: {
      title: "3. Slow target or website",
      description: "Ping and route checks for a target you enter.",
    },
    vi: {
      title: "3. Mang/web bi cham",
      description: "Ping va route cho target ban nhap.",
    },
  },
  public_service: {
    en: {
      title: "3. Internet -> my service",
      description: "Local listener plus scoped checks from the outside toward your service.",
    },
    vi: {
      title: "3. Internet -> service cua toi",
      description: "Listener local va kiem tra co scope tu ben ngoai vao service.",
    },
  },
};

export const TOOL_COPY: Record<
  string,
  Record<Locale, { name: string; description: string }>
> = {
  "local.network_state": {
    en: {
      name: "Interfaces / routes",
      description: "Show local interfaces, gateway, routes, and DNS configuration.",
    },
    vi: {
      name: "Interface / route",
      description: "Xem interface, gateway, route va DNS cau hinh tren may nay.",
    },
  },
  "local.listening_ports": {
    en: {
      name: "Local listeners",
      description: "Show ports and bind addresses listening on this machine.",
    },
    vi: {
      name: "Port dang listen",
      description: "Xem port va dia chi bind dang listen tren may nay.",
    },
  },
  "public.egress_check": {
    en: {
      name: "Egress IP + DNS",
      description:
        "Show this machine's public egress IP and the DNS path used to reach the Internet.",
    },
    vi: {
      name: "IP/DNS ra Internet",
      description:
        "Xem IP public va duong DNS ma may nay dung de di ra Internet.",
    },
  },
  "dns.leak_check": {
    en: {
      name: "DNS leak / whoami",
      description: "Compare configured DNS with resolver identity observed on the Internet.",
    },
    vi: {
      name: "DNS leak / whoami",
      description: "So sanh DNS cau hinh voi resolver ma Internet quan sat duoc.",
    },
  },
  "dns.lookup": {
    en: {
      name: "DNS lookup",
      description: "Resolve records from this machine through the selected resolver path.",
    },
    vi: {
      name: "Tra DNS target",
      description: "Resolve record tu may nay qua duong resolver dang dung.",
    },
  },
  "connectivity.ping": {
    en: {
      name: "Ping target",
      description: "Check latency, packet loss, and basic reachability from this machine.",
    },
    vi: {
      name: "Ping target",
      description: "Kiem tra latency, mat goi va reachability tu may nay.",
    },
  },
  "connectivity.traceroute": {
    en: {
      name: "Trace to target",
      description: "Show the route from this machine toward the target.",
    },
    vi: {
      name: "Trace toi target",
      description: "Xem duong di tu may nay toi target.",
    },
  },
  "connectivity.fast_trace": {
    en: {
      name: "Fast trace",
      description: "Quick route sample from this machine toward the target.",
    },
    vi: {
      name: "Trace nhanh",
      description: "Lay mau route nhanh tu may nay toi target.",
    },
  },
  "connectivity.mtr": {
    en: {
      name: "Loss by hop",
      description: "Measure latency and loss per hop from this machine.",
    },
    vi: {
      name: "Mat goi theo hop",
      description: "Do latency va mat goi theo tung hop tu may nay.",
    },
  },
  "connectivity.path_mtu": {
    en: {
      name: "Path MTU",
      description: "Estimate MTU on the path from this machine to the target.",
    },
    vi: {
      name: "Path MTU",
      description: "Uoc luong MTU tren duong tu may nay toi target.",
    },
  },
  "connectivity.route_check": {
    en: {
      name: "Route check",
      description: "Check route selection and next hop from this machine.",
    },
    vi: {
      name: "Kiem tra route",
      description: "Kiem tra route va next hop tu may nay.",
    },
  },
  "connectivity.reachability": {
    en: {
      name: "Port reachability",
      description: "Check whether this machine can reach a target host and port.",
    },
    vi: {
      name: "Reach port target",
      description: "Kiem tra may nay co toi duoc host/port target hay khong.",
    },
  },
  "web.http_probe": {
    en: {
      name: "HTTP from here",
      description: "Check HTTP status and response details from this machine.",
    },
    vi: {
      name: "HTTP tu may nay",
      description: "Kiem tra HTTP status va response tu may nay.",
    },
  },
  "web.tls_cert": {
    en: {
      name: "TLS from here",
      description: "Check TLS certificate and handshake from this machine.",
    },
    vi: {
      name: "TLS tu may nay",
      description: "Kiem tra certificate va TLS handshake tu may nay.",
    },
  },
  "public.port_check": {
    en: {
      name: "Public port from outside",
      description: "Check a scoped service from an outside vantage point.",
    },
    vi: {
      name: "Port public tu ben ngoai",
      description: "Kiem tra service co scope tu diem nhin ben ngoai.",
    },
  },
  "recon.whois_rdap": {
    en: {
      name: "RDAP / ownership",
      description: "Look up public ownership and registration data.",
    },
    vi: {
      name: "RDAP / ownership",
      description: "Tra cuu ownership va thong tin dang ky public.",
    },
  },
  "core.describe_entity": {
    en: {
      name: "Target parser",
      description: "Inspect how SonarNwork understands an entered target.",
    },
    vi: {
      name: "Parser target",
      description: "Xem SonarNwork hieu target vua nhap nhu the nao.",
    },
  },
};

export const RESULT_LABELS = {
  en: {
    summary: "Summary",
    type: "Type",
    entity: "Entity",
    target: "Target",
    resolvedIp: "Resolved IP",
    replies: "Replies",
    packetLoss: "Packet loss",
    latency: "Latency",
    hops: "Hops",
    lastHop: "Last hop",
    timeouts: "Timeouts",
    route: "Route",
    interface: "Interface",
    gateway: "Gateway",
    source: "Source",
    publicIp: "Public IP",
    dnsServers: "DNS servers",
    observedDns: "Observed DNS",
    errors: "Errors",
    localIps: "Local IPs",
    listeners: "Listeners",
    publicBinds: "Public binds",
    server: "Server",
    address: "Address",
    records: "Records",
    statusCode: "HTTP status",
    finalUrl: "Final URL",
    contentType: "Content-Type",
    title: "Title",
    security: "Security",
    protocol: "Protocol",
    subject: "Subject",
    issuer: "Issuer",
    expires: "Expires",
    handle: "Handle",
    country: "Country",
    nameservers: "Nameservers",
    entities: "Entities",
    connected: "Connected",
    remote: "Remote",
    elapsed: "Elapsed",
    exit: "Exit",
    lines: "Lines",
  },
  vi: {
    summary: "Tom tat",
    type: "Loai",
    entity: "Entity",
    target: "Target",
    resolvedIp: "IP resolve",
    replies: "Phan hoi",
    packetLoss: "Mat goi",
    latency: "Do tre",
    hops: "So hop",
    lastHop: "Hop cuoi",
    timeouts: "Timeout",
    route: "Route",
    interface: "Interface",
    gateway: "Gateway",
    source: "Nguon",
    publicIp: "IP public",
    dnsServers: "DNS server",
    observedDns: "DNS quan sat",
    errors: "Loi",
    localIps: "IP local",
    listeners: "Port listen",
    publicBinds: "Bind public",
    server: "Server",
    address: "Dia chi",
    records: "Ban ghi",
    statusCode: "HTTP status",
    finalUrl: "URL cuoi",
    contentType: "Content-Type",
    title: "Title",
    security: "Security",
    protocol: "Protocol",
    subject: "Subject",
    issuer: "Issuer",
    expires: "Het han",
    handle: "Handle",
    country: "Quoc gia",
    nameservers: "Nameserver",
    entities: "Entity",
    connected: "Ket noi",
    remote: "Remote",
    elapsed: "Thoi gian",
    exit: "Exit",
    lines: "Dong",
  },
} as const;

export const CORE_SUMMARY_LABEL_KEYS: Record<
  string,
  keyof (typeof RESULT_LABELS)["en"]
> = {
  Summary: "summary",
  Type: "type",
  Entity: "entity",
  Target: "target",
  "Resolved IP": "resolvedIp",
  Replies: "replies",
  "Packet loss": "packetLoss",
  Latency: "latency",
  Hops: "hops",
  "Last hop": "lastHop",
  Timeouts: "timeouts",
  Route: "route",
  Interface: "interface",
  Gateway: "gateway",
  Source: "source",
  "Public IP": "publicIp",
  "DNS servers": "dnsServers",
  "Observed DNS": "observedDns",
  Errors: "errors",
  "Local IPs": "localIps",
  Listeners: "listeners",
  "Public binds": "publicBinds",
  Server: "server",
  Address: "address",
  Records: "records",
  "HTTP status": "statusCode",
  "Final URL": "finalUrl",
  "Content-Type": "contentType",
  Title: "title",
  Security: "security",
  Protocol: "protocol",
  Subject: "subject",
  Issuer: "issuer",
  Expires: "expires",
  Handle: "handle",
  Country: "country",
  Nameservers: "nameservers",
  Entities: "entities",
  Connected: "connected",
  Remote: "remote",
  Elapsed: "elapsed",
  Exit: "exit",
  Lines: "lines",
};

export function toolFormRows(_probeId: string, _locale: Locale) {
  return [] as { label: string; value: string }[];
}

export function toolCopy(probe: ProbeDescriptor, _locale: Locale) {
  return {
    name: probe.name,
    description: probe.description,
  };
}
