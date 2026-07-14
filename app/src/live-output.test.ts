import { describe, expect, it, vi } from "vitest";
import {
  boundLiveConsoleLines,
  createLiveEventBuffer,
  type ProbeLiveEvent,
  type ScheduleLiveFlush,
} from "./live-output";

function liveEvent(kind: ProbeLiveEvent["kind"], values: Partial<ProbeLiveEvent> = {}) {
  return {
    run_id: "run-1",
    kind,
    done: kind === "exit",
    ...values,
  } satisfies ProbeLiveEvent;
}

function controlledScheduler() {
  let callback: (() => void) | null = null;
  const schedule: ScheduleLiveFlush = (next) => {
    callback = next;
    return () => {
      callback = null;
    };
  };
  return {
    schedule,
    run: () => {
      const next = callback;
      callback = null;
      next?.();
    },
    hasPending: () => callback !== null,
  };
}

describe("live output buffering", () => {
  it("coalesces a burst of stream lines into one state update", () => {
    const scheduler = controlledScheduler();
    const appendLines = vi.fn();
    const buffer = createLiveEventBuffer({ appendLines, schedule: scheduler.schedule });

    buffer.handle(liveEvent("stdout", { line: "one" }));
    buffer.handle(liveEvent("stderr", { line: "two" }));

    expect(appendLines).not.toHaveBeenCalled();
    expect(scheduler.hasPending()).toBe(true);
    scheduler.run();
    expect(appendLines).toHaveBeenCalledOnce();
    expect(appendLines).toHaveBeenCalledWith(["one", "[stderr] two"]);
  });

  it("flushes pending lines before the exit marker in the same update", () => {
    const scheduler = controlledScheduler();
    const appendLines = vi.fn();
    const onExit = vi.fn();
    const buffer = createLiveEventBuffer({
      appendLines,
      onExit,
      schedule: scheduler.schedule,
    });
    buffer.handle(liveEvent("stdout", { line: "tail" }));

    buffer.handle(liveEvent("exit", { exit_code: 7 }));

    expect(appendLines).toHaveBeenCalledOnce();
    expect(appendLines).toHaveBeenCalledWith(["tail", "\n[exit] code 7"]);
    expect(onExit).toHaveBeenCalledWith(7);
    expect(scheduler.hasPending()).toBe(false);
  });

  it("drops a scheduled update after disposal", () => {
    const scheduler = controlledScheduler();
    const appendLines = vi.fn();
    const buffer = createLiveEventBuffer({ appendLines, schedule: scheduler.schedule });
    buffer.handle(liveEvent("stdout", { line: "late" }));

    buffer.dispose();
    scheduler.run();

    expect(appendLines).not.toHaveBeenCalled();
  });

  it("keeps only the newest bounded console lines", () => {
    const lines = Array.from({ length: 2_010 }, (_, index) => `line-${index}`);
    const bounded = boundLiveConsoleLines(lines);

    expect(bounded).toHaveLength(2_000);
    expect(bounded[0]).toBe("line-10");
    expect(bounded[bounded.length - 1]).toBe("line-2009");
  });

  it("bounds pending output even when the animation frame is delayed", () => {
    const scheduler = controlledScheduler();
    const appendLines = vi.fn();
    const buffer = createLiveEventBuffer({ appendLines, schedule: scheduler.schedule });
    for (let index = 0; index < 2_010; index += 1) {
      buffer.handle(liveEvent("stdout", { line: `line-${index}` }));
    }

    buffer.handle(liveEvent("exit", { exit_code: 0 }));

    const batch = appendLines.mock.calls[0][0] as string[];
    expect(batch).toHaveLength(2_000);
    expect(batch[0]).toBe("line-11");
    expect(batch[batch.length - 1]).toBe("\n[exit] code 0");
  });

  it("uses UTF-8 bytes when truncating an oversized unicode line", () => {
    const bounded = boundLiveConsoleLines(["đ".repeat(600_000)]);

    expect(new TextEncoder().encode(bounded[0]).byteLength).toBeLessThanOrEqual(1024 * 1024);
    expect(bounded[0].startsWith("…")).toBe(true);
  });
});
