import { describe, expect, it } from "vitest";
import {
  defaultScannerProfileFromCatalog,
  scannerHasField,
  scannerNamespace,
  scannerProfileOptionsFromCatalog,
} from "./interaction";
import type { InteractionCatalog, InteractionNamespace } from "./interaction";

function scanner(
  toolId: string,
  profileChoices: Array<[string, string]> = [],
  includePorts = false,
): InteractionNamespace {
  return {
    id: `scanner.${toolId}`,
    trigger: `/${toolId}`,
    aliases: [],
    label: toolId,
    description: `${toolId} scanner`,
    group: "scanner",
    action_class: "active_scan",
    capabilities: ["status", "preview", "run", "stop"],
    examples: [],
    fields: [
      {
        id: "target",
        label: "Target",
        help: "Target accepted by the scanner",
        kind: "target",
        required: true,
        choices: [],
      },
      ...(profileChoices.length > 0
        ? [{
            id: "profile",
            label: "Profile",
            help: "Tool-specific profile",
            kind: "choice" as const,
            required: true,
            default_value: profileChoices[0][0],
            choices: profileChoices.map(([value, label]) => ({ value, label, help: label })),
          }]
        : []),
      ...(includePorts
        ? [{
            id: "ports",
            label: "Ports",
            help: "Port selection",
            kind: "choice" as const,
            required: true,
            default_value: "top",
            choices: [],
          }]
        : []),
    ],
  };
}

const catalog: InteractionCatalog = {
  schema_version: 2,
  namespaces: [
    scanner("nmap", [
      ["nmap_top_ports", "Top ports"],
      ["nmap_service_deep", "Deep service"],
    ], true),
    scanner("nuclei", [
      ["nuclei_safe", "Safe"],
      ["nuclei_full", "Full"],
    ]),
  ],
};

describe("interaction catalog adapter", () => {
  it("keeps Nmap and Nuclei options isolated", () => {
    expect(scannerProfileOptionsFromCatalog(catalog, "nmap").map((choice) => choice.id))
      .toEqual(["fast", "deep"]);
    expect(scannerProfileOptionsFromCatalog(catalog, "nuclei").map((choice) => choice.id))
      .toEqual(["safe", "full"]);
  });

  it("derives defaults and port visibility from the shared schema", () => {
    expect(defaultScannerProfileFromCatalog(catalog, "nmap")).toBe("fast");
    expect(defaultScannerProfileFromCatalog(catalog, "nuclei")).toBe("safe");
    expect(scannerHasField(catalog, "nmap", "ports")).toBe(true);
    expect(scannerHasField(catalog, "nuclei", "ports")).toBe(false);
  });

  it("does not classify unknown plugins as scanners", () => {
    expect(scannerNamespace(catalog, "unknown")).toBeUndefined();
  });
});
