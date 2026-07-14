export type InteractionGroup =
  | "diagnose"
  | "scanner"
  | "tooling"
  | "remote"
  | "capture"
  | "inventory"
  | "monitor"
  | "history";

export type InteractionCapability =
  | "status"
  | "install"
  | "update"
  | "preview"
  | "run"
  | "stop"
  | "open_in_cli"
  | "view"
  | "delete"
  | "clear";

export type InteractionFieldKind =
  | "target"
  | "text"
  | "integer"
  | "choice"
  | "toggle"
  | "ports";

export type InteractionChoice = {
  value: string;
  label: string;
  help: string;
};

export type InteractionVisibility = {
  field_id: string;
  equals: string;
};

export type InteractionField = {
  id: string;
  label: string;
  help: string;
  kind: InteractionFieldKind;
  required: boolean;
  default_value?: string | null;
  placeholder?: string | null;
  choices: InteractionChoice[];
  visible_when?: InteractionVisibility | null;
};

export type InteractionNamespace = {
  id: string;
  trigger: string;
  aliases: string[];
  label: string;
  description: string;
  group: InteractionGroup;
  action_class: string;
  requires_scope_confirmation: boolean;
  fields: InteractionField[];
  capabilities: InteractionCapability[];
  examples: string[];
};

export type InteractionCatalog = {
  schema_version: number;
  namespaces: InteractionNamespace[];
};

export type DesktopScannerProfileId =
  | "fast"
  | "version"
  | "deep"
  | "udp_quick"
  | "safe"
  | "http_exposure"
  | "known_vulns"
  | "full";

export type ScannerProfileOption = {
  id: DesktopScannerProfileId;
  label: string;
  description: string;
};

const CORE_PROFILE_TO_DESKTOP: Record<string, DesktopScannerProfileId> = {
  nmap_top_ports: "fast",
  nmap_version: "version",
  nmap_service_deep: "deep",
  nmap_udp_quick: "udp_quick",
  nuclei_safe: "safe",
  nuclei_http_exposure: "http_exposure",
  nuclei_known_vulns: "known_vulns",
  nuclei_full: "full",
};

export function scannerNamespace(
  catalog: InteractionCatalog | null | undefined,
  toolId: string,
): InteractionNamespace | undefined {
  return catalog?.namespaces.find((namespace) => namespace.id === `scanner.${toolId}`);
}

export function scannerField(
  catalog: InteractionCatalog | null | undefined,
  toolId: string,
  fieldId: string,
): InteractionField | undefined {
  return scannerNamespace(catalog, toolId)?.fields.find((field) => field.id === fieldId);
}

export function scannerHasField(
  catalog: InteractionCatalog | null | undefined,
  toolId: string,
  fieldId: string,
): boolean {
  return Boolean(scannerField(catalog, toolId, fieldId));
}

export function scannerProfileOptionsFromCatalog(
  catalog: InteractionCatalog | null | undefined,
  toolId: string,
): ScannerProfileOption[] {
  const field = scannerField(catalog, toolId, "profile");
  if (!field) {
    return [];
  }

  return field.choices.flatMap((choice) => {
    const id = CORE_PROFILE_TO_DESKTOP[choice.value];
    return id ? [{ id, label: choice.label, description: choice.help }] : [];
  });
}

export function defaultScannerProfileFromCatalog(
  catalog: InteractionCatalog | null | undefined,
  toolId: string,
): DesktopScannerProfileId | undefined {
  const defaultValue = scannerField(catalog, toolId, "profile")?.default_value;
  return defaultValue ? CORE_PROFILE_TO_DESKTOP[defaultValue] : undefined;
}
