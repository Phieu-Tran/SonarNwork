import {
  Activity,
  Cable,
  CircleDot,
  Compass,
  Database,
  Globe2,
  LockKeyhole,
  Network,
  Radar,
  Route,
  Search,
  Server,
  ShieldCheck,
  SquareTerminal,
  Wifi,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

export type ProbeCategory =
  | "core"
  | "connectivity"
  | "local_network"
  | "public_exposure"
  | "dns"
  | "recon"
  | "web_tls"
  | "intelligence";

export type ProbeStatus = "ready" | "planned" | "disabled";

export type ProbeDescriptor = {
  id: string;
  name: string;
  description: string;
  category: ProbeCategory;
  status: ProbeStatus;
  risk: string;
  requirements: unknown[];
};

export type Locale = "en" | "vi";

export type ProbeTargetInput =
  | { type: "input"; value: string }
  | { type: "local_machine" }
  | { type: "current_internet_path" };

export type WorkflowDescriptor = {
  id: string;
  title_key: string;
  description_key: string;
  target: ProbeTargetInput;
  primary_probe_ids: string[];
  advanced_probe_ids: string[];
};

export type ToolGroupId =
  | "local_machine"
  | "internet_path"
  | "public_remote"
  | "web_tls"
  | "recon"
  | "core";

export type ToolGroupMeta = {
  id: ToolGroupId;
  title: string;
  short: string;
  icon: LucideIcon;
  includes: (probe: ProbeDescriptor) => boolean;
};

const RECON_CATEGORIES = new Set<ProbeCategory>(["recon", "intelligence"]);

const LOCAL_CHECK_PROBES = new Set([
  "connectivity.ping",
  "connectivity.traceroute",
  "connectivity.fast_trace",
  "connectivity.mtr",
  "connectivity.path_mtu",
  "connectivity.route_check",
  "connectivity.reachability",
  "local.network_state",
  "local.listening_ports",
  "dns.lookup",
]);

const INTERNET_PATH_PROBES = new Set(["public.egress_check", "dns.leak_check"]);
const PUBLIC_REMOTE_PROBES = new Set(["public.port_check"]);
const TARGETLESS_PROBES = new Set([
  "connectivity.route_check",
  "dns.leak_check",
  "local.network_state",
  "local.listening_ports",
  "public.egress_check",
]);

export const TOOL_GROUPS: ToolGroupMeta[] = [
  {
    id: "local_machine",
    title: "Local machine",
    short: "LOC",
    icon: Network,
    includes: (probe) => LOCAL_CHECK_PROBES.has(probe.id),
  },
  {
    id: "internet_path",
    title: "Internet path",
    short: "NET",
    icon: Globe2,
    includes: (probe) => INTERNET_PATH_PROBES.has(probe.id),
  },
  {
    id: "public_remote",
    title: "Public remote",
    short: "PUB",
    icon: Radar,
    includes: (probe) => PUBLIC_REMOTE_PROBES.has(probe.id),
  },
  {
    id: "web_tls",
    title: "Web / TLS",
    short: "TLS",
    icon: LockKeyhole,
    includes: (probe) => probe.category === "web_tls",
  },
  {
    id: "recon",
    title: "Recon / Intel",
    short: "REC",
    icon: Compass,
    includes: (probe) => RECON_CATEGORIES.has(probe.category),
  },
  {
    id: "core",
    title: "Core",
    short: "SYS",
    icon: SquareTerminal,
    includes: (probe) => probe.category === "core",
  },
];

const TOOL_ICONS: Record<string, LucideIcon> = {
  "connectivity.ping": Activity,
  "connectivity.traceroute": Route,
  "connectivity.fast_trace": Route,
  "connectivity.mtr": Activity,
  "connectivity.path_mtu": Cable,
  "connectivity.route_check": Cable,
  "connectivity.reachability": Wifi,
  "local.network_state": Network,
  "local.listening_ports": Server,
  "dns.lookup": Database,
  "dns.leak_check": ShieldCheck,
  "public.port_check": Radar,
  "public.egress_check": Globe2,
  "recon.whois_rdap": Search,
  "web.http_probe": Globe2,
  "web.tls_cert": LockKeyhole,
  "core.describe_entity": SquareTerminal,
};

const WORKFLOW_ICONS: Record<string, LucideIcon> = {
  internet_path: Globe2,
  local_network: Network,
  public_service: Radar,
};

const BEGINNER_PROBE_ORDER = [
  "local.network_state",
  "local.listening_ports",
  "public.egress_check",
  "connectivity.ping",
  "connectivity.traceroute",
  "dns.leak_check",
  "dns.lookup",
  "web.http_probe",
  "web.tls_cert",
  "connectivity.reachability",
  "connectivity.fast_trace",
  "connectivity.mtr",
  "connectivity.path_mtu",
  "connectivity.route_check",
  "public.port_check",
  "recon.whois_rdap",
  "core.describe_entity",
];

export function getToolIcon(probe: ProbeDescriptor): LucideIcon {
  return (
    TOOL_ICONS[probe.id] ??
    TOOL_GROUPS.find((group) => group.includes(probe))?.icon ??
    CircleDot
  );
}

export function getWorkflowIcon(workflowId: string): LucideIcon {
  return WORKFLOW_ICONS[workflowId] ?? CircleDot;
}

export function groupForProbe(probe: ProbeDescriptor): ToolGroupMeta {
  return TOOL_GROUPS.find((group) => group.includes(probe)) ?? TOOL_GROUPS[0];
}

export function beginnerProbeRank(probeId: string) {
  const rank = BEGINNER_PROBE_ORDER.indexOf(probeId);
  return rank >= 0 ? rank : BEGINNER_PROBE_ORDER.length;
}

export function toolNeedsTarget(probe: ProbeDescriptor) {
  return !TARGETLESS_PROBES.has(probe.id);
}

export function probeAcceptsPort(probeId: string) {
  return new Set([
    "connectivity.reachability",
    "public.port_check",
    "web.http_probe",
    "web.tls_cert",
  ]).has(probeId);
}

export function probeRequiresRemoteVantage(probeId: string) {
  return probeId === "public.port_check";
}

export function defaultPortForProbe(_probeId: string) {
  return "443";
}

export function probeTarget(
  probe: ProbeDescriptor,
  target: string,
  targetPort: string,
): ProbeTargetInput {
  if (!toolNeedsTarget(probe)) {
    return probe.id.startsWith("local.") || probe.id === "connectivity.route_check"
      ? { type: "local_machine" }
      : { type: "current_internet_path" };
  }

  const cleanTarget = target.trim();
  const cleanPort = normalizePort(targetPort);
  if (!probeAcceptsPort(probe.id) || !cleanPort) {
    return { type: "input", value: cleanTarget };
  }

  return { type: "input", value: targetWithPort(cleanTarget, cleanPort) };
}

export function extractPort(value: string) {
  const clean = value.trim();
  if (/^[a-z][a-z\d+.-]*:\/\//i.test(clean)) {
    try {
      const url = new URL(clean);
      return url.port || "";
    } catch {
      return "";
    }
  }

  const bracketedIpv6 = clean.match(/^\[[^\]]+\]:(\d{1,5})$/);
  if (bracketedIpv6) {
    return normalizePort(bracketedIpv6[1]);
  }

  if ((clean.match(/:/g) ?? []).length > 1) {
    return "";
  }

  const match = clean.match(/:(\d{1,5})$/);
  return match ? normalizePort(match[1]) : "";
}

export function probeScopeLabel(probeId: string, locale: Locale) {
  const labels = {
    en: {
      local: "on this machine",
      resolver: "this machine -> DNS",
      outbound: "this machine -> target",
      remote: "internet -> service",
      path: "this machine -> internet",
      passive: "public lookup",
    },
    vi: {
      local: "tren may nay",
      resolver: "may nay -> DNS",
      outbound: "may nay -> target",
      remote: "internet -> service",
      path: "may nay -> internet",
      passive: "tra cứu public",
    },
  } as const;

  if (probeId === "dns.lookup") {
    return labels[locale].resolver;
  }
  if (probeId.startsWith("local.")) {
    return labels[locale].local;
  }
  if (probeId === "public.egress_check" || probeId === "dns.leak_check") {
    return labels[locale].path;
  }
  if (probeId === "public.port_check") {
    return labels[locale].remote;
  }
  if (probeId.startsWith("web.") || probeId.startsWith("connectivity.")) {
    return labels[locale].outbound;
  }
  if (probeId.startsWith("recon.")) {
    return labels[locale].passive;
  }

  return labels[locale].local;
}

function normalizePort(value: string) {
  const clean = value.trim();
  if (!/^\d{1,5}$/.test(clean)) {
    return "";
  }

  const port = Number(clean);
  return port > 0 && port <= 65535 ? String(port) : "";
}

function targetWithPort(target: string, port: string) {
  if (!target) {
    return target;
  }

  try {
    const url = new URL(target);
    url.port = port;
    return url.toString();
  } catch {
    // Keep going for host/IP inputs.
  }

  const bracketedIpv6 = target.match(/^\[([^\]]+)\](?::\d{1,5})?$/);
  if (bracketedIpv6) {
    return `[${bracketedIpv6[1]}]:${port}`;
  }

  if ((target.match(/:/g) ?? []).length > 1) {
    return `[${target}]:${port}`;
  }

  const ipv4WithPort = target.match(/^(.+):(\d{1,5})$/);
  if (ipv4WithPort && !target.includes("://")) {
    return `${ipv4WithPort[1]}:${port}`;
  }

  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(target)) {
    return `${target}:${port}`;
  }

  return `https://${target.replace(/:\d{1,5}$/, "")}:${port}`;
}

