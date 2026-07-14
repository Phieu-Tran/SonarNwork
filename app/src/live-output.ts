export type ProbeLiveEvent = {
  run_id: string;
  kind: "start" | "stdout" | "stderr" | "exit";
  line?: string | null;
  command?: string | null;
  exit_code?: number | null;
  done: boolean;
};

export type ScheduleLiveFlush = (callback: () => void) => () => void;

type LiveEventBufferOptions = {
  appendLines: (lines: string[]) => void;
  onStart?: (command: string) => void;
  onExit?: (exitCode: number | null) => void;
  schedule?: ScheduleLiveFlush;
};

const LIVE_CONSOLE_MAX_LINES = 2_000;
const LIVE_CONSOLE_MAX_BYTES = 1024 * 1024;
const UTF8 = new TextEncoder();

export function boundLiveConsoleLines(lines: string[]): string[] {
  const normalized = lines.map((line) => truncateUtf8Tail(line, LIVE_CONSOLE_MAX_BYTES));
  let bytes = 0;
  let start = normalized.length;

  for (let index = normalized.length - 1; index >= 0; index -= 1) {
    const lineBytes = utf8Length(normalized[index]);
    if (start < normalized.length && bytes + lineBytes > LIVE_CONSOLE_MAX_BYTES) {
      break;
    }
    bytes += lineBytes;
    start = index;
    if (normalized.length - start >= LIVE_CONSOLE_MAX_LINES) {
      break;
    }
  }

  return normalized.slice(start);
}

export function createLiveEventBuffer(options: LiveEventBufferOptions) {
  const schedule = options.schedule ?? scheduleOnNextFrame;
  let pending: string[] = [];
  let pendingBytes = 0;
  let cancelScheduled: (() => void) | null = null;
  let disposed = false;

  function flushNow(additionalLines: string[] = []) {
    cancelScheduled?.();
    cancelScheduled = null;
    if (disposed) {
      pending = [];
      return;
    }
    const batch = boundLiveConsoleLines([...pending, ...additionalLines]);
    pending = [];
    pendingBytes = 0;
    if (batch.length > 0) {
      options.appendLines(batch);
    }
  }

  function scheduleFlush() {
    if (cancelScheduled || disposed) {
      return;
    }
    cancelScheduled = schedule(() => {
      cancelScheduled = null;
      flushNow();
    });
  }

  function handle(event: ProbeLiveEvent) {
    if (disposed) {
      return;
    }
    if (event.kind === "start" && event.command) {
      options.onStart?.(event.command);
      return;
    }
    if ((event.kind === "stdout" || event.kind === "stderr") && event.line) {
      const line = event.kind === "stderr" ? `[stderr] ${event.line}` : event.line;
      pending.push(line);
      pendingBytes += utf8Length(line);
      if (pending.length > LIVE_CONSOLE_MAX_LINES || pendingBytes > LIVE_CONSOLE_MAX_BYTES) {
        pending = boundLiveConsoleLines(pending);
        pendingBytes = pending.reduce((total, item) => total + utf8Length(item), 0);
      }
      scheduleFlush();
      return;
    }
    if (event.kind === "exit") {
      const exitCode = event.exit_code ?? null;
      flushNow([`\n[exit] code ${exitCode ?? "unknown"}`]);
      options.onExit?.(exitCode);
    }
  }

  function dispose() {
    disposed = true;
    cancelScheduled?.();
    cancelScheduled = null;
    pending = [];
    pendingBytes = 0;
  }

  return { dispose, flushNow, handle };
}

function scheduleOnNextFrame(callback: () => void) {
  if (typeof requestAnimationFrame === "function") {
    const frame = requestAnimationFrame(callback);
    return () => cancelAnimationFrame(frame);
  }
  const timer = globalThis.setTimeout(callback, 16);
  return () => globalThis.clearTimeout(timer);
}

function utf8Length(value: string) {
  return UTF8.encode(value).byteLength;
}

function truncateUtf8Tail(value: string, maxBytes: number) {
  if (utf8Length(value) <= maxBytes) {
    return value;
  }
  const ellipsis = "…";
  const budget = maxBytes - utf8Length(ellipsis);
  let lower = 0;
  let upper = value.length;
  while (lower < upper) {
    const middle = Math.floor((lower + upper) / 2);
    if (utf8Length(value.slice(middle)) <= budget) {
      upper = middle;
    } else {
      lower = middle + 1;
    }
  }
  let start = lower;
  if (
    start > 0 &&
    start < value.length &&
    value.charCodeAt(start) >= 0xdc00 &&
    value.charCodeAt(start) <= 0xdfff &&
    value.charCodeAt(start - 1) >= 0xd800 &&
    value.charCodeAt(start - 1) <= 0xdbff
  ) {
    start += 1;
  }
  while (start < value.length && utf8Length(value.slice(start)) > budget) {
    start += 1;
  }
  return `${ellipsis}${value.slice(start)}`;
}
