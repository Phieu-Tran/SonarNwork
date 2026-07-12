import { describe, expect, it } from "vitest";

import { liveExitCodeFromLines, resultVerdict } from "./App";

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
