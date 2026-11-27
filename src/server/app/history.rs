//! A [`reedline::History`] backed by the `command_history` table.
//!
//! reedline's trait is synchronous and is called on every keystroke that
//! touches history, while the repository is async. The bridge: the user's
//! rows are preloaded into memory when the prompt session starts
//! ([`history`]), every save appends to that cache and hands the row to a
//! spawned drain task through a bounded channel, and every read answers from
//! the cache — the same shape as `FileBackedHistory`, which is also all in
//! memory. A failure to write costs the line its persistence, never the
//! session its prompt.

use std::sync::Arc;

use log::warn;
use reedline::{
    CommandLineSearch, FileBackedHistory, History, HistoryItem, HistoryItemId, HistoryTimestamp,
    ReedlineError, ReedlineErrorVariants, SearchDirection, SearchQuery,
};
use sea_orm::ActiveValue::{NotSet, Set};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::database::entity::command_history;
use crate::database::models::{CommandHistory, HistoryScope};
use crate::server::HandlerBackend;

/// One pending change the drain task is to write to the table.
#[derive(Debug, PartialEq)]
enum HistoryWrite {
    Append {
        command_line: String,
        created_at: i64,
    },
    Delete {
        id: i64,
    },
    Clear,
}

/// The per-session half of [`history`]: the preloaded rows plus a sender to
/// the drain task.
pub(crate) struct DbHistory {
    /// The rows this prompt can recall, oldest first, capped at `cap`.
    entries: std::collections::VecDeque<HistoryItem>,
    /// The id the next save takes. Stays above every preloaded id so
    /// "greater id" keeps meaning "more recent" within the session.
    next_id: i64,
    /// The first id this session assigned. Below it, an id names a real row
    /// and a delete must reach the table; at or above it, the id is
    /// cache-only (the drain task's inserts take their own row ids).
    first_local_id: i64,
    cap: usize,
    tx: mpsc::Sender<HistoryWrite>,
}

impl DbHistory {
    /// Build the cache from a `list_history` result. Rows past `cap` from
    /// the old end are dropped — the drain task's prune holds the table to
    /// the same size.
    fn from_rows(rows: Vec<CommandHistory>, cap: usize, tx: mpsc::Sender<HistoryWrite>) -> Self {
        let first = rows.len().saturating_sub(cap);
        let mut entries = std::collections::VecDeque::with_capacity(rows.len());
        for row in rows.into_iter().skip(first) {
            let mut item = HistoryItem::from_command_line(row.command_line);
            item.id = Some(HistoryItemId::new(row.id));
            item.start_timestamp = Some(HistoryTimestamp::from_millis(row.created_at));
            entries.push_back(item);
        }
        let next_id = entries
            .back()
            .and_then(|e| e.id)
            .map(|id| id.0 + 1)
            .unwrap_or(1);
        Self {
            entries,
            next_id,
            first_local_id: next_id,
            cap,
            tx,
        }
    }
}

/// Load a user's rows for one scope and return the history to hand to
/// `Reedline::with_history`. `history_size = 0` keeps the prompts exactly as
/// they were: a history that stores nothing.
pub(crate) async fn history<B: 'static + HandlerBackend + Send + Sync>(
    backend: &Arc<B>,
    user_id: Uuid,
    scope: HistoryScope,
) -> Box<dyn History> {
    let cap = backend.history_size();
    if cap == 0 {
        return Box::new(FileBackedHistory::new(0).expect("a zero capacity is valid"));
    }
    let rows = backend
        .db_repository()
        .list_history(user_id, scope)
        .await
        .unwrap_or_else(|e| {
            warn!("history preload failed for user {user_id} ({scope}): {e}");
            Vec::new()
        });
    let (tx, rx) = mpsc::channel(1024);
    let writer = Arc::clone(backend);
    tokio::spawn(drain(writer, user_id, scope, cap, rx));
    Box::new(DbHistory::from_rows(rows, cap, tx))
}

/// Write one queued change. Errors are logged by the caller and the loop
/// continues: a failed write must not take the prompt down with it.
async fn apply<B: HandlerBackend>(
    backend: &B,
    user_id: Uuid,
    scope: HistoryScope,
    cap: usize,
    write: HistoryWrite,
) -> Result<(), crate::database::error::DatabaseError> {
    let repo = backend.db_repository();
    match write {
        HistoryWrite::Append {
            command_line,
            created_at,
        } => {
            repo.insert_history(command_history::ActiveModel {
                id: NotSet,
                user_id: Set(user_id),
                scope: Set(scope),
                command_line: Set(command_line),
                created_at: Set(created_at),
            })
            .await?;
            repo.prune_history(user_id, scope, cap).await
        }
        HistoryWrite::Delete { id } => repo.delete_history(id).await,
        HistoryWrite::Clear => repo.clear_history(user_id, scope).await,
    }
}

/// Consume the history channel until the prompt closes it. Runs for the
/// lifetime of one [`DbHistory`]; the sender dropping is the exit.
async fn drain<B: HandlerBackend>(
    backend: Arc<B>,
    user_id: Uuid,
    scope: HistoryScope,
    cap: usize,
    mut rx: mpsc::Receiver<HistoryWrite>,
) {
    while let Some(write) = rx.recv().await {
        if let Err(e) = apply(&*backend, user_id, scope, cap, write).await {
            warn!("history write failed for user {user_id} ({scope}): {e}");
        }
    }
}

impl History for DbHistory {
    fn save(&mut self, h: HistoryItem) -> reedline::Result<HistoryItem> {
        let mut item = h;
        // A consecutive duplicate, an empty line or no room at all: nothing
        // is stored, and a returned id of None says so.
        if item.command_line.is_empty()
            || self.cap == 0
            || self
                .entries
                .back()
                .is_some_and(|e| e.command_line == item.command_line)
        {
            item.id = None;
            return Ok(item);
        }
        let created_at = item
            .start_timestamp
            .map(HistoryTimestamp::to_millis)
            .unwrap_or(HistoryTimestamp::now().to_millis());
        item.id = Some(HistoryItemId::new(self.next_id));
        self.next_id += 1;
        item.start_timestamp = Some(HistoryTimestamp::from_millis(created_at));
        let queued = HistoryWrite::Append {
            command_line: item.command_line.clone(),
            created_at,
        };
        self.entries.push_back(item.clone());
        while self.entries.len() > self.cap {
            self.entries.pop_front();
        }
        if self.tx.try_send(queued).is_err() {
            warn!("history writes fell behind; the line is kept for this session only");
        }
        Ok(item)
    }

    fn load(&self, id: HistoryItemId) -> reedline::Result<HistoryItem> {
        self.entries
            .iter()
            .find(|e| e.id == Some(id))
            .cloned()
            .ok_or(ReedlineError(ReedlineErrorVariants::OtherHistoryError(
                "Item does not exist",
            )))
    }

    fn count(&self, query: SearchQuery) -> reedline::Result<i64> {
        Ok(self.search(query)?.len() as i64)
    }

    fn search(&self, query: SearchQuery) -> reedline::Result<Vec<HistoryItem>> {
        if query.filter.hostname.is_some()
            || query.filter.cwd_exact.is_some()
            || query.filter.cwd_prefix.is_some()
            || query.filter.exit_successful.is_some()
        {
            return Err(ReedlineError(
                ReedlineErrorVariants::HistoryFeatureUnsupported {
                    history: "DbHistory",
                    feature: "filtering by extra info",
                },
            ));
        }
        // The FileBackedHistory window: `start_id` and `end_id` are
        // exclusive bounds, each taking the role the direction gives it —
        // Backward walks ids below `start_id` newest first, Forward walks
        // ids above it oldest first. A session filter is ignored on
        // purpose: crossing sessions is the point of a persisted history.
        let (lower_id, upper_id) = match query.direction {
            SearchDirection::Backward => (query.end_id, query.start_id),
            SearchDirection::Forward => (query.start_id, query.end_id),
        };
        // The cursor skips the line it sits on through a crate-private
        // filter field. Every query carrying a `start_id` comes from the
        // cursor holding that very entry, so the entry's own line is the
        // skip — derived here instead of read.
        let skip_line = query.start_id.and_then(|id| {
            self.entries
                .iter()
                .find(|e| e.id == Some(id))
                .map(|e| e.command_line.clone())
        });
        let matches = |e: &HistoryItem| -> bool {
            let id = e.id.map(|i| i.0).unwrap_or(i64::MIN);
            if let Some(bound) = lower_id.map(|b| b.0)
                && id <= bound
            {
                return false;
            }
            if let Some(bound) = upper_id.map(|b| b.0)
                && id >= bound
            {
                return false;
            }
            if let Some(ts) = e.start_timestamp.map(HistoryTimestamp::to_millis) {
                if let Some(bound) = query.start_time.map(|t| t.to_millis()) {
                    let ok = match query.direction {
                        SearchDirection::Backward => ts <= bound,
                        SearchDirection::Forward => ts >= bound,
                    };
                    if !ok {
                        return false;
                    }
                }
                if let Some(bound) = query.end_time.map(|t| t.to_millis()) {
                    let ok = match query.direction {
                        SearchDirection::Backward => ts >= bound,
                        SearchDirection::Forward => ts <= bound,
                    };
                    if !ok {
                        return false;
                    }
                }
            }
            if skip_line.as_deref() == Some(e.command_line.as_str()) {
                return false;
            }
            match &query.filter.command_line {
                Some(CommandLineSearch::Prefix(p)) => e.command_line.starts_with(p),
                Some(CommandLineSearch::Substring(p)) => e.command_line.contains(p),
                Some(CommandLineSearch::Exact(p)) => p == &e.command_line,
                None => true,
            }
        };
        let mut found: Vec<&HistoryItem> = self.entries.iter().filter(|e| matches(e)).collect();
        if query.direction == SearchDirection::Backward {
            found.reverse();
        }
        let found = match query.limit {
            Some(limit) => found.into_iter().take(limit.max(0) as usize).collect(),
            None => found,
        };
        Ok(found.into_iter().cloned().collect())
    }

    fn update(
        &mut self,
        id: HistoryItemId,
        updater: &dyn Fn(HistoryItem) -> HistoryItem,
    ) -> reedline::Result<()> {
        // Nothing in this crate calls `Reedline::update_last_command_context`,
        // so this never runs. Cache-only by design: the row the drain task
        // wrote is the record, and a local edit does not rewrite it.
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == Some(id)) {
            *entry = updater(entry.clone());
        }
        Ok(())
    }

    fn clear(&mut self) -> reedline::Result<()> {
        self.entries.clear();
        if self.tx.try_send(HistoryWrite::Clear).is_err() {
            warn!("history writes fell behind; the clear is kept for this session only");
        }
        Ok(())
    }

    fn delete(&mut self, h: HistoryItemId) -> reedline::Result<()> {
        if let Some(pos) = self.entries.iter().position(|e| e.id == Some(h)) {
            self.entries.remove(pos);
        }
        // Below `first_local_id` the id names a real row; at or above it
        // the id was only ever cache-local, and the row keeps its own.
        if h.0 < self.first_local_id && self.tx.try_send(HistoryWrite::Delete { id: h.0 }).is_err()
        {
            warn!("history writes fell behind; the delete is kept for this session only");
        }
        Ok(())
    }

    fn sync(&mut self) -> std::io::Result<()> {
        // Every save is handed to the drain task as it happens; there is
        // nothing to flush from this side, and the channel cannot be
        // drained synchronously anyway.
        Ok(())
    }

    fn session(&self) -> Option<reedline::HistorySessionId> {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use reedline::SearchFilter;

    /// The queries reedline's `HistoryCursor` issues, rebuilt from the
    /// public types. The cursor itself is private to the reedline crate, so
    /// these tests replay its exact searches: `start_id` plus `limit: 1`
    /// in either direction. The cursor also sets the crate-private
    /// `not_command_line` to the line it is sitting on — [`DbHistory`]
    /// derives that skip from `start_id` instead, and these tests prove the
    /// navigation behaves the same.
    struct Nav {
        current: Option<HistoryItem>,
    }

    impl Nav {
        fn new() -> Self {
            Nav { current: None }
        }

        fn step(
            &mut self,
            history: &dyn History,
            direction: SearchDirection,
            filter: SearchFilter,
        ) {
            if direction == SearchDirection::Forward && self.current.is_none() {
                return;
            }
            let start_id = self.current.as_ref().and_then(|e| e.id);
            let next = history
                .search(SearchQuery {
                    start_id,
                    end_id: None,
                    start_time: None,
                    end_time: None,
                    direction,
                    limit: Some(1),
                    filter,
                })
                .unwrap();
            match next.into_iter().next() {
                Some(item) => self.current = Some(item),
                None if direction == SearchDirection::Forward => self.current = None,
                None => {}
            }
        }

        fn back(&mut self, history: &dyn History) {
            self.step(
                history,
                SearchDirection::Backward,
                SearchFilter::anything(None),
            );
        }

        fn forward(&mut self, history: &dyn History) {
            self.step(
                history,
                SearchDirection::Forward,
                SearchFilter::anything(None),
            );
        }

        fn jump_to_oldest(&mut self, history: &dyn History, filter: SearchFilter) -> bool {
            let mut oldest = history
                .search(SearchQuery {
                    direction: SearchDirection::Forward,
                    ..SearchQuery::last_with_search(filter)
                })
                .unwrap();
            let Some(oldest) = oldest.pop() else {
                return false;
            };
            if self.current.as_ref().map(|e| e.id) == Some(oldest.id) {
                return false;
            }
            self.current = Some(oldest);
            true
        }

        fn string(&self) -> Option<String> {
            self.current.as_ref().map(|e| e.command_line.clone())
        }
    }

    fn prefix(p: &str) -> SearchFilter {
        SearchFilter::from_text_search(CommandLineSearch::Prefix(p.to_string()), None)
    }

    fn substring(p: &str) -> SearchFilter {
        SearchFilter::from_text_search(CommandLineSearch::Substring(p.to_string()), None)
    }

    /// A history over rows `("line", millis)` pairs, plus its receiver.
    fn built(rows: &[(&str, i64)], cap: usize) -> (DbHistory, mpsc::Receiver<HistoryWrite>) {
        let (tx, rx) = mpsc::channel(64);
        let rows = rows
            .iter()
            .enumerate()
            .map(|(i, (line, at))| CommandHistory {
                id: i as i64 + 1,
                command_line: line.to_string(),
                created_at: *at,
            })
            .collect();
        (DbHistory::from_rows(rows, cap, tx), rx)
    }

    fn save(history: &mut dyn History, line: &str) -> HistoryItem {
        history.save(HistoryItem::from_command_line(line)).unwrap()
    }

    fn lines(history: &dyn History) -> Vec<String> {
        history
            .search(SearchQuery::everything(SearchDirection::Forward, None))
            .unwrap()
            .iter()
            .map(|e| e.command_line.clone())
            .collect()
    }

    fn append(line: &str, at: i64) -> HistoryWrite {
        HistoryWrite::Append {
            command_line: line.to_string(),
            created_at: at,
        }
    }

    #[test]
    fn going_backwards_bottoms_out() {
        let (history, _rx) = built(&[("command1", 1), ("command2", 2)], 100);
        let mut nav = Nav::new();
        for _ in 0..5 {
            nav.back(&history);
        }
        assert_eq!(nav.string(), Some("command1".to_string()));
    }

    #[test]
    fn going_forwards_from_none_stays_none() {
        let (history, _rx) = built(&[("command1", 1), ("command2", 2)], 100);
        let mut nav = Nav::new();
        for _ in 0..5 {
            nav.forward(&history);
        }
        assert_eq!(nav.string(), None);
    }

    #[test]
    fn back_and_forward_return_to_none() {
        let (history, _rx) = built(&[("command1", 1), ("command2", 2)], 100);
        let mut nav = Nav::new();
        nav.back(&history);
        nav.back(&history);
        assert_eq!(nav.string(), Some("command1".to_string()));
        nav.forward(&history);
        assert_eq!(nav.string(), Some("command2".to_string()));
        nav.forward(&history);
        nav.forward(&history);
        assert_eq!(nav.string(), None);
    }

    #[test]
    fn prefix_search_works_and_bottoms_out() {
        let (mut history, _rx) = built(&[], 100);
        save(&mut history, "find me as well");
        save(&mut history, "test");
        save(&mut history, "find me");
        let mut nav = Nav::new();
        nav.step(&history, SearchDirection::Backward, prefix("find"));
        assert_eq!(nav.string(), Some("find me".to_string()));
        nav.step(&history, SearchDirection::Backward, prefix("find"));
        assert_eq!(nav.string(), Some("find me as well".to_string()));
        for _ in 0..3 {
            nav.step(&history, SearchDirection::Backward, prefix("find"));
        }
        assert_eq!(nav.string(), Some("find me as well".to_string()));
    }

    #[test]
    fn substring_search_works() {
        let (mut history, _rx) = built(&[], 100);
        for line in [
            "substring",
            "don't find me either",
            "prefix substring",
            "don't find me",
            "prefix substring suffix",
        ] {
            save(&mut history, line);
        }
        let mut nav = Nav::new();
        nav.step(&history, SearchDirection::Backward, substring("substring"));
        assert_eq!(nav.string(), Some("prefix substring suffix".to_string()));
        nav.step(&history, SearchDirection::Backward, substring("substring"));
        assert_eq!(nav.string(), Some("prefix substring".to_string()));
        nav.step(&history, SearchDirection::Backward, substring("substring"));
        assert_eq!(nav.string(), Some("substring".to_string()));
    }

    /// The cursor's `not_command_line` skip, which `DbHistory` derives from
    /// `start_id`: going back from a line must not recall the same text
    /// again, only an older, different one.
    #[test]
    fn back_navigation_skips_the_line_the_cursor_sits_on() {
        let (mut history, _rx) = built(&[], 100);
        save(&mut history, "find me as well");
        save(&mut history, "find me once");
        save(&mut history, "test");
        save(&mut history, "find me once");
        let mut nav = Nav::new();
        nav.step(&history, SearchDirection::Backward, prefix("find"));
        assert_eq!(nav.string(), Some("find me once".to_string()));
        nav.step(&history, SearchDirection::Backward, prefix("find"));
        assert_eq!(nav.string(), Some("find me as well".to_string()));
    }

    #[test]
    fn jump_to_oldest_jumps_and_then_stays() {
        let (mut history, _rx) = built(&[], 100);
        for line in ["one", "two", "one"] {
            save(&mut history, line);
        }
        let mut nav = Nav::new();
        assert!(nav.jump_to_oldest(&history, SearchFilter::anything(None)));
        assert_eq!(nav.string(), Some("one".to_string()));
        assert!(!nav.jump_to_oldest(&history, SearchFilter::anything(None)));
        nav.forward(&history);
        assert_eq!(nav.string(), Some("two".to_string()));
    }

    #[test]
    fn jump_to_oldest_honors_the_prefix() {
        let (mut history, _rx) = built(&[], 100);
        for line in ["test", "find me first", "find me"] {
            save(&mut history, line);
        }
        let mut nav = Nav::new();
        assert!(nav.jump_to_oldest(&history, prefix("find")));
        assert_eq!(nav.string(), Some("find me first".to_string()));
    }

    #[test]
    fn consecutive_duplicates_are_not_saved() {
        let (mut history, _rx) = built(&[], 100);
        for line in ["unique_old", "test", "test", "unique"] {
            save(&mut history, line);
        }
        assert_eq!(history.count_all().unwrap(), 3);
    }

    #[test]
    fn save_stamps_the_time_and_queues_the_append() {
        let (mut history, mut rx) = built(&[], 100);
        let item = save(&mut history, "echo hello");
        let stamp = item.start_timestamp.expect("save stamps the time");
        assert!(stamp.to_millis() > 0);
        assert_eq!(item.id, Some(HistoryItemId::new(1)));
        assert_eq!(
            rx.try_recv().unwrap(),
            append("echo hello", stamp.to_millis())
        );
    }

    #[test]
    fn a_dropped_duplicate_save_queues_nothing() {
        let (mut history, mut rx) = built(&[], 100);
        save(&mut history, "same");
        save(&mut history, "same");
        assert!(
            matches!(&rx.try_recv().unwrap(), HistoryWrite::Append { command_line, .. }
                if command_line == "same")
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn search_ignores_a_session_filter() {
        let (history, _rx) = built(&[("one", 1), ("two", 2)], 100);
        let filter = SearchFilter::anything(Some(reedline::HistorySessionId::new(7)));
        let found = history
            .search(SearchQuery {
                filter,
                ..SearchQuery::everything(SearchDirection::Forward, None)
            })
            .unwrap();
        assert_eq!(found.len(), 2, "up-arrow crosses sessions");
    }

    #[test]
    fn unsupported_filters_error() {
        let (history, _rx) = built(&[("one", 1)], 100);
        let hostname = {
            let mut filter = SearchFilter::anything(None);
            filter.hostname = Some("foohost".to_string());
            filter
        };
        let cwd_exact = {
            let mut filter = SearchFilter::anything(None);
            filter.cwd_exact = Some("/".to_string());
            filter
        };
        let exit_successful = {
            let mut filter = SearchFilter::anything(None);
            filter.exit_successful = Some(true);
            filter
        };
        for filter in [hostname, cwd_exact, exit_successful] {
            let err = history
                .search(SearchQuery {
                    filter,
                    ..SearchQuery::everything(SearchDirection::Forward, None)
                })
                .unwrap_err();
            assert!(
                matches!(
                    err.0,
                    ReedlineErrorVariants::HistoryFeatureUnsupported { .. }
                ),
                "expected HistoryFeatureUnsupported, got {err:?}"
            );
        }
    }

    #[test]
    fn time_filters_bound_the_window() {
        let (history, _rx) = built(&[("old", 100), ("middle", 200), ("new", 300)], 100);
        let times = |query: SearchQuery| -> Vec<i64> {
            history
                .search(query)
                .unwrap()
                .iter()
                .map(|e| e.start_timestamp.unwrap().to_millis())
                .collect()
        };
        // Backward starts at the newest side: start_time caps it.
        assert_eq!(
            times(SearchQuery {
                start_time: Some(HistoryTimestamp::from_millis(250)),
                ..SearchQuery::everything(SearchDirection::Backward, None)
            }),
            vec![200, 100]
        );
        // Forward starts at the oldest side: start_time raises it.
        assert_eq!(
            times(SearchQuery {
                start_time: Some(HistoryTimestamp::from_millis(150)),
                ..SearchQuery::everything(SearchDirection::Forward, None)
            }),
            vec![200, 300]
        );
        // end_time stops the walk on the far side: Forward ends before it.
        assert_eq!(
            times(SearchQuery {
                end_time: Some(HistoryTimestamp::from_millis(250)),
                ..SearchQuery::everything(SearchDirection::Forward, None)
            }),
            vec![100, 200]
        );
    }

    #[test]
    fn clear_empties_the_cache_and_is_queued_after_the_appends() {
        let (mut history, mut rx) = built(&[("old", 1)], 100);
        save(&mut history, "one");
        history.clear().unwrap();
        assert_eq!(history.count_all().unwrap(), 0);
        assert!(matches!(
            rx.try_recv().unwrap(),
            HistoryWrite::Append { .. }
        ));
        assert_eq!(rx.try_recv().unwrap(), HistoryWrite::Clear);
    }

    #[test]
    fn deleting_a_preloaded_row_id_reaches_the_table() {
        let (mut history, mut rx) = built(&[("one", 1), ("two", 2)], 100);
        history.delete(HistoryItemId::new(1)).unwrap();
        assert_eq!(lines(&history), vec!["two"]);
        assert_eq!(rx.try_recv().unwrap(), HistoryWrite::Delete { id: 1 });
    }

    #[test]
    fn deleting_a_local_id_touches_only_the_cache() {
        let (mut history, mut rx) = built(&[], 100);
        let item = save(&mut history, "session-only");
        history.delete(item.id.unwrap()).unwrap();
        assert_eq!(history.count_all().unwrap(), 0);
        assert!(matches!(
            rx.try_recv().unwrap(),
            HistoryWrite::Append { .. }
        ));
        assert!(rx.try_recv().is_err(), "no delete for a cache-only id");
    }

    #[test]
    fn capacity_evicts_the_oldest() {
        let (mut history, _rx) = built(&[("one", 1), ("two", 2)], 3);
        for line in ["three", "four", "five"] {
            save(&mut history, line);
        }
        assert_eq!(lines(&history), vec!["three", "four", "five"]);
    }

    #[test]
    fn preload_truncates_to_the_newest_cap() {
        let (history, _rx) = built(&[("one", 1), ("two", 2), ("three", 3)], 2);
        assert_eq!(lines(&history), vec!["two", "three"]);
    }
}
