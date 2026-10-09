use std::collections::VecDeque;
use std::time::{Duration, Instant};

use nettrace_packet::{LinkType, Timestamp};

use crate::{DriverStats, LiveError, LivePacket, LiveSource};

/// Feeds prepared frames as if they arrived live, with a fixed gap between
/// packets. Used by tests and demos; behaves like a real interface that goes
/// quiet after the last frame.
pub struct ReplaySource {
    link: LinkType,
    frames: VecDeque<(Timestamp, Vec<u8>)>,
    gap: Duration,
    next_at: Instant,
    delivered: u64,
}

impl ReplaySource {
    pub fn new(link: LinkType, frames: Vec<(Timestamp, Vec<u8>)>, gap: Duration) -> Self {
        ReplaySource { link, frames: frames.into(), gap, next_at: Instant::now(), delivered: 0 }
    }
}

impl LiveSource for ReplaySource {
    fn link_type(&self) -> LinkType {
        self.link
    }

    fn next_packet(&mut self, buf: &mut Vec<u8>, timeout: Duration) -> Result<Option<LivePacket>, LiveError> {
        if self.frames.is_empty() {
            std::thread::sleep(timeout.min(Duration::from_millis(10)));
            return Ok(None);
        }
        let now = Instant::now();
        if now < self.next_at {
            let wait = self.next_at - now;
            if wait > timeout {
                std::thread::sleep(timeout);
                return Ok(None);
            }
            std::thread::sleep(wait);
        }
        let Some((ts, frame)) = self.frames.pop_front() else { return Ok(None) };
        buf.clear();
        buf.extend_from_slice(&frame);
        self.next_at = Instant::now() + self.gap;
        self.delivered += 1;
        Ok(Some(LivePacket { ts, origlen: frame.len() as u32 }))
    }

    fn stats(&mut self) -> Option<DriverStats> {
        Some(DriverStats { received: self.delivered, dropped: 0, if_dropped: 0 })
    }

    fn finished(&self) -> bool {
        self.frames.is_empty()
    }
}
