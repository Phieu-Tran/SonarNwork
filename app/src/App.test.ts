import { describe, expect, it } from "vitest";

import {
  boundLiveConsoleLines,
  defaultScannerPorts,
  liveExitCodeFromLines,
  partitionWorkflowNavigation,
  resultVerdict,
} from "./App";

describe("workflow navigation", () => {
  it("keeps workflows in the top bar and moves installable packages to the sidebar", () => {
    const workflows = [
      { id: "local_network" },
      { id: "internet_path" },
      { id: "tool_nmap" },
      { id: "tool_globalping" },
      { id: "tool_httpx" },
      { id: "tool_operations" },
    ];

    const navigation = partitionWorkflowNavigation(workflows);

    expect(navigation.topWorkflows.map((workflow) => workflow.id)).toEqual([
      "local_network",
      "internet_path",
      "tool_globalping",
      "tool_operations",
    ]);
    expect(navigation.packageWorkflows.map((workflow) => workflow.id)).toEqual([
      "tool_nmap",
      "tool_httpx",
    ]);
  });
});

describe("scanner defaults", () => {
  it("uses the bounded top-port scan for the desktop runner", () => {
    expect(defaultScannerPorts()).toBe("top");
  });
});

describe("boundLiveConsoleLines", () => {
  it("retains only the newest 2,000 streamed lines", () => {
    const lines = Array.from({ length: 2_001 }, (_, index) => `line-${index}`);
    const bounded = boundLiveConsoleLines(lines);

    expect(bounded).toHaveLength(2_000);
    expect(bounded[0]).toBe("line-1");
    expect(bounded[bounded.length - 1]).toBe("line-2000");
  });

  it("caps a single oversized line to the byte budget", () => {
    const bounded = boundLiveConsoleLines(["x".repeat(1024 * 1024 + 5)]);

    expect(bounded).toHaveLength(1);
    expect(new TextEncoder().encode(bounded[0])).toHaveLength(1024 * 1024);
  });
});

describe("liveExitCodeFromLines", () => {
  it("parses explicit exit markers", () => {
    expect(liveExitCodeFromLines(["$ ping 192.0.2.1", "[exit] code 1"])).toBe(1);
  });

  it("parses completed live-command summaries", () => {
    expect(
      liveExitCodeFromLines([
        "$ SonarNwork CLI: ping",
        "[done] ping 192.0.2.1 exited with 1",
      ]),
    ).toBe(1);
  });
});

describe("resultVerdict (live path, E3)", () => {
  const verdict = (liveLines: string[], liveExitCode: number | null, isLiveRunning = false) =>
    resultVerdict(null, liveLines, liveExitCode, isLiveRunning, false, undefined, "en");

  it("marks a non-zero exit as failed", () => {
    expect(verdict(["$ ping 192.0.2.1", "[exit] code 1"], 1).status).toBe("failed");
  });

  it("marks a confirmed zero exit as ok", () => {
    expect(verdict(["$ ping 1.1.1.1", "[exit] code 0"], 0).status).toBe("ok");
  });

  it("does NOT show green when the exit code is unknown (E3 regression lock)", () => {
    // Completed live command whose exit code could not be determined must never
    // read as a green "completed" verdict.
    expect(verdict(["$ some-tool run", "[exit] code unknown"], null).status).toBe("unknown");
  });

  it("stays unknown while the command is still running", () => {
    expect(verdict(["$ ping 1.1.1.1"], null, true).status).toBe("unknown");
  });
});
