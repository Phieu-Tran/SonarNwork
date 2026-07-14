import { describe, expect, it } from "vitest";
import { buildSavedRunInput, toggleComparisonSelection } from "./history";

describe("diagnostic history", () => {
  it("builds a saved result from interpreted output", () => {
    const result = {
      descriptor: { id: "connectivity.ping", name: "Ping" },
      output: { summary: "raw", summary_rows: [{ label: "Latency", value: "20 ms" }] },
      interpretation: {
        verdict: { status: "ok" },
        summary: "healthy",
        summary_rows: [{ label: "Latency", value: "18 ms" }],
      },
    };
    expect(buildSavedRunInput(result, " 127.0.0.1 ")).toMatchObject({
      probe_id: "connectivity.ping",
      target: "127.0.0.1",
      verdict: "ok",
      summary: "healthy",
      summary_rows: [{ label: "Latency", value: "18 ms" }],
    });
  });

  it("keeps at most two results selected for comparison", () => {
    expect(toggleComparisonSelection(["one", "two"], "three")).toEqual(["two", "three"]);
  });
});
