use std::sync::mpsc::Sender;
use std::thread;
use std::time::{Duration, Instant};

use ratatui::crossterm::event;

use super::runner::RunnerEvent;

pub(super) const OUTPUT_SCROLL_PAGE: usize = 10;

#[derive(Debug)]
pub(super) enum UiEvent {
    Terminal(event::Event),
    TerminalError(String),
    Runner(RunnerEvent),
}

pub(super) fn spawn_terminal_reader(sender: Sender<UiEvent>) {
    thread::spawn(move || loop {
        match event::read() {
            Ok(event) => {
                if sender.send(UiEvent::Terminal(event)).is_err() {
                    return;
                }
            }
            Err(error) => {
                let _ = sender.send(UiEvent::TerminalError(error.to_string()));
                return;
            }
        }
    });
}

/// Coalesces bursts of state changes and limits terminal paints without polling while idle.
pub(super) struct FramePacer {
    min_interval: Duration,
    last_render: Option<Instant>,
    dirty: bool,
}

impl FramePacer {
    pub(super) fn new(max_frames_per_second: u32) -> Self {
        let frames = max_frames_per_second.max(1);
        Self {
            min_interval: Duration::from_secs_f64(1.0 / f64::from(frames)),
            last_render: None,
            dirty: false,
        }
    }

    pub(super) fn request(&mut self) {
        self.dirty = true;
    }

    pub(super) fn should_render(&self) -> bool {
        self.should_render_at(Instant::now())
    }

    pub(super) fn rendered(&mut self) {
        self.rendered_at(Instant::now());
    }

    pub(super) fn wait_timeout(&self) -> Option<Duration> {
        self.wait_timeout_at(Instant::now())
    }

    fn should_render_at(&self, now: Instant) -> bool {
        self.dirty
            && self
                .last_render
                .is_none_or(|last| now.saturating_duration_since(last) >= self.min_interval)
    }

    fn rendered_at(&mut self, now: Instant) {
        self.last_render = Some(now);
        self.dirty = false;
    }

    fn wait_timeout_at(&self, now: Instant) -> Option<Duration> {
        if !self.dirty {
            return None;
        }
        Some(self.last_render.map_or(Duration::ZERO, |last| {
            self.min_interval
                .saturating_sub(now.saturating_duration_since(last))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_requests_until_the_next_frame_is_due() {
        let base = Instant::now();
        let mut pacer = FramePacer::new(50);
        pacer.request();
        assert!(pacer.should_render_at(base));
        pacer.rendered_at(base);

        pacer.request();
        pacer.request();
        assert!(!pacer.should_render_at(base + Duration::from_millis(10)));
        assert_eq!(
            pacer.wait_timeout_at(base + Duration::from_millis(10)),
            Some(Duration::from_millis(10))
        );
        assert!(pacer.should_render_at(base + Duration::from_millis(20)));
    }

    #[test]
    fn waits_indefinitely_when_no_frame_was_requested() {
        let pacer = FramePacer::new(60);
        assert_eq!(pacer.wait_timeout_at(Instant::now()), None);
    }
}
