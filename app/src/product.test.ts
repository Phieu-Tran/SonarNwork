import { describe, expect, it } from "vitest";

import {
  beginnerProbeRank,
  extractPort,
  probeAcceptsPort,
  probeRequiresRemoteVantage,
  probeTarget,
  toolNeedsTarget,
  type ProbeDescriptor,
} from "./product";

function probe(id: string): ProbeDescriptor {
  return {
    id,
    name: id,
    description: "",
    category: "connectivity",
    status: "ready",
    risk: "safe_active",
    requirements: [],
  };
}

describe("probeTarget", () => {
  it("maps local and current-path probes to targetless variants", () => {
    expect(probeTarget(probe("local.network_state"), "ignored", "")).toEqual({
      type: "local_machine",
    });
    expect(probeTarget(probe("connectivity.route_check"), "ignored", "")).toEqual({
      type: "local_machine",
    });
    expect(probeTarget(probe("public.egress_check"), "ignored", "")).toEqual({
      type: "current_internet_path",
    });
  });

  it("trims ordinary input targets", () => {
    expect(probeTarget(probe("connectivity.ping"), " 1.1.1.1 ", "443")).toEqual({
      type: "input",
      value: "1.1.1.1",
    });
  });

  it("adds or replaces ports for supported probes", () => {
    const reachability = probe("connectivity.reachability");
    expect(probeTarget(reachability, "192.0.2.10", " 8443 ")).toEqual({
      type: "input",
      value: "192.0.2.10:8443",
    });
    expect(probeTarget(reachability, "192.0.2.10:80", "443")).toEqual({
      type: "input",
      value: "192.0.2.10:443",
    });
    expect(probeTarget(probe("web.http_probe"), "https://example.com:8080/path", "443")).toEqual({
      type: "input",
      value: "https://example.com/path",
    });
  });

  it("formats bare and bracketed IPv6 socket targets", () => {
    const reachability = probe("connectivity.reachability");
    expect(probeTarget(reachability, "2001:db8::1", "443")).toEqual({
      type: "input",
      value: "[2001:db8::1]:443",
    });
    expect(probeTarget(reachability, "[2001:db8::1]:80", "8443")).toEqual({
      type: "input",
      value: "[2001:db8::1]:8443",
    });
  });

  it("ignores invalid ports instead of changing the target", () => {
    expect(probeTarget(probe("web.tls_cert"), "example.com", "70000")).toEqual({
      type: "input",
      value: "example.com",
    });
  });
});

describe("port and workflow helpers", () => {
  it("extracts valid ports without treating bare IPv6 suffixes as ports", () => {
    expect(extractPort("https://example.com:8443/path")).toBe("8443");
    expect(extractPort("example.com:53")).toBe("53");
    expect(extractPort("[2001:db8::1]:443")).toBe("443");
    expect(extractPort("2001:db8::1")).toBe("");
    expect(extractPort("example.com:70000")).toBe("");
  });

  it("keeps remote-vantage and target requirements explicit", () => {
    expect(probeAcceptsPort("public.port_check")).toBe(true);
    expect(probeRequiresRemoteVantage("public.port_check")).toBe(true);
    expect(probeRequiresRemoteVantage("connectivity.reachability")).toBe(false);
    expect(toolNeedsTarget(probe("dns.leak_check"))).toBe(false);
    expect(toolNeedsTarget(probe("dns.lookup"))).toBe(true);
  });

  it("ranks known beginner probes before unknown probes", () => {
    expect(beginnerProbeRank("connectivity.ping")).toBeLessThan(
      beginnerProbeRank("custom.future_probe"),
    );
  });
});
