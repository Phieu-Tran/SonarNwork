import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  FolderOpen,
  GitCompareArrows,
  History,
  LoaderCircle,
  Search,
  Trash2,
} from "lucide-react";

type SummaryFact = { label: string; value: string };

export type SavedRunSummary = {
  id: string;
  created_at: string;
  probe_id: string;
  probe_name: string;
  target: string;
  verdict: string;
  summary: string;
};

export type SavedRun = SavedRunSummary & {
  summary_rows: SummaryFact[];
  result: unknown;
};

type ProbeRunSnapshot = {
  descriptor: { id: string; name: string };
  output: { summary?: string; summary_rows?: SummaryFact[] };
  interpretation?: {
    verdict?: { status: string };
    summary?: string | null;
    summary_rows: SummaryFact[];
  };
};

type RunComparison = {
  left: SavedRunSummary;
  right: SavedRunSummary;
  verdict_changed: boolean;
  fact_changes: Array<{
    label: string;
    before?: string;
    after?: string;
    kind: "added" | "removed" | "changed";
  }>;
};

export function buildSavedRunInput(result: ProbeRunSnapshot, target: string) {
  const interpretedRows = result.interpretation?.summary_rows ?? [];
  return {
    probe_id: result.descriptor.id,
    probe_name: result.descriptor.name,
    target: target.trim(),
    verdict: result.interpretation?.verdict?.status ?? "unknown",
    summary: result.interpretation?.summary ?? result.output.summary ?? "",
    summary_rows: interpretedRows.length > 0 ? interpretedRows : result.output.summary_rows ?? [],
    result,
  };
}

export function toggleComparisonSelection(selected: string[], id: string) {
  if (selected.includes(id)) return selected.filter((candidate) => candidate !== id);
  return [...selected.slice(-1), id];
}

export async function saveCompletedRun(result: ProbeRunSnapshot, target: string) {
  return invoke<SavedRunSummary>("save_probe_run", {
    input: buildSavedRunInput(result, target),
  });
}

type Props = {
  locale: string;
  refreshToken: number;
  onOpenRun: (run: SavedRun) => void;
  onStorageError: (message: string) => void;
};

export function HistoryPanel({ locale, refreshToken, onOpenRun, onStorageError }: Props) {
  const vi = locale === "vi";
  const [query, setQuery] = useState("");
  const [runs, setRuns] = useState<SavedRunSummary[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [comparison, setComparison] = useState<RunComparison | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  async function loadRuns(nextQuery = query) {
    setIsLoading(true);
    try {
      const saved = await invoke<SavedRunSummary[]>("list_probe_runs", {
        query: nextQuery.trim() || null,
      });
      setRuns(saved);
      setSelected((items) => items.filter((id) => saved.some((run) => run.id === id)));
    } catch (error) {
      onStorageError(String(error));
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void loadRuns();
    // Refresh only after a completed run is persisted.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshToken]);

  async function openRun(id: string) {
    try {
      onOpenRun(await invoke<SavedRun>("get_probe_run", { id }));
    } catch (error) {
      onStorageError(String(error));
    }
  }

  async function deleteRun(id: string) {
    try {
      await invoke("delete_probe_run", { id });
      setComparison(null);
      await loadRuns();
    } catch (error) {
      onStorageError(String(error));
    }
  }

  async function compareRuns() {
    if (selected.length !== 2) return;
    try {
      setComparison(
        await invoke<RunComparison>("compare_probe_runs", {
          leftId: selected[0],
          rightId: selected[1],
        }),
      );
    } catch (error) {
      setComparison(null);
      onStorageError(String(error));
    }
  }

  return (
    <section className="historyPanel" aria-label={vi ? "Lịch sử chẩn đoán" : "Diagnostic history"}>
      <div className="historyPanelHeader">
        <h2><History size={19} /> {vi ? "Lịch sử chẩn đoán" : "Diagnostic history"}</h2>
      </div>

      <div className="historySection historyOnlySection">
        <div className="historySectionTitle">
          <h3>{vi ? "Kết quả đã lưu" : "Saved results"}</h3>
          <button type="button" className="secondaryButton" disabled={selected.length !== 2} onClick={() => void compareRuns()}>
            <GitCompareArrows size={16} /> {vi ? "So sánh" : "Compare"}
          </button>
        </div>
        <form className="historySearch" onSubmit={(event) => { event.preventDefault(); void loadRuns(); }}>
          <Search size={16} />
          <input
            name="history-search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={vi ? "Tìm mục tiêu, kiểm tra, kết luận…" : "Search target, check, verdict…"}
            aria-label={vi ? "Tìm lịch sử" : "Search history"}
          />
        </form>
        <p className="historySelectionHint">
          {vi
            ? "Chọn đúng hai lần chạy để xem phần thay đổi."
            : "Select exactly two runs to compare their changes."}
        </p>
        <div className="historyList">
          {isLoading ? (
            <div className="historyEmptyState loading" role="status">
              <LoaderCircle size={20} />
              <strong>{vi ? "Đang tải lịch sử" : "Loading history"}</strong>
              <span>{vi ? "Đang đọc các lần chạy đã lưu…" : "Reading saved runs…"}</span>
            </div>
          ) : runs.length > 0 ? runs.map((run) => (
            <article className="historyItem" key={run.id}>
              <input
                name={`history-compare-${run.id}`}
                type="checkbox"
                checked={selected.includes(run.id)}
                onChange={() => setSelected((items) => toggleComparisonSelection(items, run.id))}
                aria-label={vi ? `Chọn ${run.probe_name} để so sánh` : `Select ${run.probe_name} for comparison`}
              />
              <button type="button" className="historyItemMain" onClick={() => void openRun(run.id)}>
                <strong>{run.probe_name} <span className={`historyVerdict ${run.verdict}`}>{run.verdict}</span></strong>
                <span>{run.target || (vi ? "Máy hiện tại" : "This machine")} · {new Date(run.created_at).toLocaleString(locale)}</span>
                {run.summary && <small>{run.summary}</small>}
              </button>
              <button type="button" className="iconButton" onClick={() => void deleteRun(run.id)} aria-label={vi ? "Xóa kết quả" : "Delete result"}>
                <Trash2 size={15} />
              </button>
            </article>
          )) : (
            <div className="historyEmptyState">
              <FolderOpen size={22} />
              <strong>
                {query.trim()
                  ? vi ? "Không tìm thấy lần chạy phù hợp" : "No matching runs"
                  : vi ? "Chưa có lần chạy nào được lưu" : "No saved runs yet"}
              </strong>
              <span>
                {query.trim()
                  ? vi ? "Thử rút gọn từ khóa tìm kiếm." : "Try a shorter search term."
                  : vi ? "Kết quả hoàn tất sẽ xuất hiện tại đây." : "Completed results will appear here."}
              </span>
            </div>
          )}
        </div>
      </div>

      {comparison && (
        <div className="comparisonPanel">
          <h3>{vi ? "Thay đổi giữa hai lần kiểm tra" : "Changes between runs"}</h3>
          {comparison.verdict_changed && <p>{comparison.left.verdict} → {comparison.right.verdict}</p>}
          {comparison.fact_changes.map((change) => (
            <div className="comparisonRow" key={change.label}>
              <strong>{change.label}</strong>
              <span>{change.before ?? "—"}</span><span>→</span><span>{change.after ?? "—"}</span>
            </div>
          ))}
          {!comparison.verdict_changed && comparison.fact_changes.length === 0 && (
            <p>{vi ? "Không có thay đổi trong phần tóm tắt." : "No summary changes."}</p>
          )}
        </div>
      )}
    </section>
  );
}
