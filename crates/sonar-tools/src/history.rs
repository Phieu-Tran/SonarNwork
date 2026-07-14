use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

const STORE_VERSION: u32 = 1;
const MAX_RUNS: usize = 500;
const STORE_FILE: &str = "history-v1.json";

pub struct HistoryService {
    path: PathBuf,
    gate: Mutex<()>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SummaryFact {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SaveRunInput {
    pub probe_id: String,
    pub probe_name: String,
    pub target: String,
    pub verdict: String,
    pub summary: String,
    #[serde(default)]
    pub summary_rows: Vec<SummaryFact>,
    pub result: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SavedRun {
    pub id: String,
    pub created_at: String,
    pub probe_id: String,
    pub probe_name: String,
    pub target: String,
    pub verdict: String,
    pub summary: String,
    pub summary_rows: Vec<SummaryFact>,
    pub result: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SavedRunSummary {
    pub id: String,
    pub created_at: String,
    pub probe_id: String,
    pub probe_name: String,
    pub target: String,
    pub verdict: String,
    pub summary: String,
}

impl From<&SavedRun> for SavedRunSummary {
    fn from(run: &SavedRun) -> Self {
        Self {
            id: run.id.clone(),
            created_at: run.created_at.clone(),
            probe_id: run.probe_id.clone(),
            probe_name: run.probe_name.clone(),
            target: run.target.clone(),
            verdict: run.verdict.clone(),
            summary: run.summary.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FactChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FactChange {
    pub label: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub kind: FactChangeKind,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RunComparison {
    pub left: SavedRunSummary,
    pub right: SavedRunSummary,
    pub verdict_changed: bool,
    pub fact_changes: Vec<FactChange>,
}

#[derive(Debug, Deserialize, Serialize)]
struct HistoryStore {
    version: u32,
    #[serde(default)]
    runs: Vec<SavedRun>,
}

impl Default for HistoryStore {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            runs: Vec::new(),
        }
    }
}

impl HistoryService {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            path: data_dir.into().join(STORE_FILE),
            gate: Mutex::new(()),
        }
    }

    pub fn save(&self, input: SaveRunInput) -> Result<SavedRunSummary, String> {
        let _guard = self.lock()?;
        if input.probe_id.trim().is_empty() || input.probe_name.trim().is_empty() {
            return Err("probe ID and name cannot be empty".into());
        }
        let mut store = self.load()?;
        let run = SavedRun {
            id: Uuid::new_v4().to_string(),
            created_at: Utc::now().to_rfc3339(),
            probe_id: input.probe_id.trim().to_owned(),
            probe_name: input.probe_name.trim().to_owned(),
            target: input.target.trim().to_owned(),
            verdict: input.verdict.trim().to_owned(),
            summary: input.summary.trim().to_owned(),
            summary_rows: input.summary_rows,
            result: input.result,
        };
        store.runs.push(run.clone());
        store
            .runs
            .sort_by(|left, right| right.created_at.cmp(&left.created_at));
        store.runs.truncate(MAX_RUNS);
        self.write(&store)?;
        Ok(SavedRunSummary::from(&run))
    }

    pub fn list(&self, query: Option<&str>) -> Result<Vec<SavedRunSummary>, String> {
        let _guard = self.lock()?;
        let mut runs = self.load()?.runs;
        runs.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        let query = query.unwrap_or_default().trim().to_lowercase();
        Ok(runs
            .iter()
            .filter(|run| {
                query.is_empty()
                    || [
                        run.probe_id.as_str(),
                        run.probe_name.as_str(),
                        run.target.as_str(),
                        run.verdict.as_str(),
                        run.summary.as_str(),
                    ]
                    .iter()
                    .any(|value| value.to_lowercase().contains(&query))
            })
            .map(SavedRunSummary::from)
            .collect())
    }

    pub fn get(&self, id: &str) -> Result<SavedRun, String> {
        let _guard = self.lock()?;
        self.load()?
            .runs
            .into_iter()
            .find(|run| run.id == id)
            .ok_or_else(|| format!("saved run `{id}` was not found"))
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        let _guard = self.lock()?;
        let mut store = self.load()?;
        let original_len = store.runs.len();
        store.runs.retain(|run| run.id != id);
        if store.runs.len() == original_len {
            return Err(format!("saved run `{id}` was not found"));
        }
        self.write(&store)
    }

    pub fn compare(&self, left_id: &str, right_id: &str) -> Result<RunComparison, String> {
        let _guard = self.lock()?;
        let store = self.load()?;
        let left = store
            .runs
            .iter()
            .find(|run| run.id == left_id)
            .ok_or_else(|| format!("saved run `{left_id}` was not found"))?;
        let right = store
            .runs
            .iter()
            .find(|run| run.id == right_id)
            .ok_or_else(|| format!("saved run `{right_id}` was not found"))?;
        if left.probe_id != right.probe_id
            || normalize_target(&left.target) != normalize_target(&right.target)
        {
            return Err("only runs of the same probe and target can be compared".into());
        }

        let before: BTreeMap<&str, &str> = left
            .summary_rows
            .iter()
            .map(|fact| (fact.label.as_str(), fact.value.as_str()))
            .collect();
        let after: BTreeMap<&str, &str> = right
            .summary_rows
            .iter()
            .map(|fact| (fact.label.as_str(), fact.value.as_str()))
            .collect();
        let mut labels: Vec<&str> = before.keys().chain(after.keys()).copied().collect();
        labels.sort_unstable();
        labels.dedup();
        let fact_changes = labels
            .into_iter()
            .filter_map(|label| match (before.get(label), after.get(label)) {
                (Some(old), Some(new)) if old != new => Some(FactChange {
                    label: label.into(),
                    before: Some((*old).into()),
                    after: Some((*new).into()),
                    kind: FactChangeKind::Changed,
                }),
                (Some(old), None) => Some(FactChange {
                    label: label.into(),
                    before: Some((*old).into()),
                    after: None,
                    kind: FactChangeKind::Removed,
                }),
                (None, Some(new)) => Some(FactChange {
                    label: label.into(),
                    before: None,
                    after: Some((*new).into()),
                    kind: FactChangeKind::Added,
                }),
                _ => None,
            })
            .collect();
        Ok(RunComparison {
            left: SavedRunSummary::from(left),
            right: SavedRunSummary::from(right),
            verdict_changed: left.verdict != right.verdict,
            fact_changes,
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>, String> {
        self.gate
            .lock()
            .map_err(|_| "saved diagnostics store lock is poisoned".to_owned())
    }

    fn load(&self) -> Result<HistoryStore, String> {
        if !self.path.exists() {
            return Ok(HistoryStore::default());
        }
        let bytes = fs::read(&self.path)
            .map_err(|error| format!("could not read saved diagnostics: {error}"))?;
        let store: HistoryStore = serde_json::from_slice(&bytes)
            .map_err(|error| format!("saved diagnostics file is malformed: {error}"))?;
        if store.version != STORE_VERSION {
            return Err(format!(
                "unsupported saved diagnostics schema version {}",
                store.version
            ));
        }
        Ok(store)
    }

    fn write(&self, store: &HistoryStore) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!("could not create saved diagnostics directory: {error}")
            })?;
        }
        let temporary = self.path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("could not create saved diagnostics update: {error}"))?;
        let payload = serde_json::to_vec_pretty(store)
            .map_err(|error| format!("could not serialize saved diagnostics: {error}"))?;
        if let Err(error) = file.write_all(&payload).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(&temporary);
            return Err(format!("could not write saved diagnostics: {error}"));
        }
        drop(file);
        fs::rename(&temporary, &self.path).map_err(|error| {
            let _ = fs::remove_file(&temporary);
            format!("could not install saved diagnostics update: {error}")
        })
    }
}

fn normalize_target(target: &str) -> String {
    target.trim().trim_end_matches('/').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_dir() -> PathBuf {
        std::env::temp_dir().join(format!("sonarnwork-history-{}", Uuid::new_v4()))
    }

    fn input(target: &str, verdict: &str, value: &str) -> SaveRunInput {
        SaveRunInput {
            probe_id: "connectivity.ping".into(),
            probe_name: "Ping".into(),
            target: target.into(),
            verdict: verdict.into(),
            summary: "summary".into(),
            summary_rows: vec![SummaryFact {
                label: "latency".into(),
                value: value.into(),
            }],
            result: serde_json::json!({ "ok": true }),
        }
    }

    #[test]
    fn saves_lists_compares_and_deletes_runs() {
        let path = temporary_dir();
        let history = HistoryService::new(&path);
        let left = history.save(input("EXAMPLE.com/", "ok", "10 ms")).unwrap();
        let right = history
            .save(input("example.com", "warning", "30 ms"))
            .unwrap();
        assert_eq!(history.list(Some("example")).unwrap().len(), 2);
        let comparison = history.compare(&left.id, &right.id).unwrap();
        assert!(comparison.verdict_changed);
        assert_eq!(comparison.fact_changes.len(), 1);
        history.delete(&left.id).unwrap();
        assert_eq!(history.list(None).unwrap().len(), 1);
        let _ = fs::remove_dir_all(path);
    }
}
