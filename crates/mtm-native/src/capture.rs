use serde::{Deserialize, Serialize};

pub const MAX_CAPTURE_BYTES: usize = 1_048_576;
pub const CAPTURE_HEAD_BYTES: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapturePayload {
    pub text: String,
    pub total_bytes: usize,
    pub retained_bytes: usize,
    pub dropped_bytes: usize,
    pub truncated: bool,
}

#[derive(Clone, Debug)]
pub struct BoundedCapture {
    limit: usize,
    head_limit: usize,
    head: Vec<u8>,
    tail: Vec<u8>,
    total_bytes: usize,
}

impl Default for BoundedCapture {
    fn default() -> Self {
        Self::new(MAX_CAPTURE_BYTES, CAPTURE_HEAD_BYTES)
    }
}

impl BoundedCapture {
    #[must_use]
    pub fn new(limit: usize, head_limit: usize) -> Self {
        let bounded_head = head_limit.min(limit);
        Self {
            limit,
            head_limit: bounded_head,
            head: Vec::with_capacity(bounded_head),
            tail: Vec::with_capacity(limit.saturating_sub(bounded_head)),
            total_bytes: 0,
        }
    }

    pub fn append(&mut self, chunk: &[u8]) {
        self.total_bytes = self.total_bytes.saturating_add(chunk.len());
        let remaining_head = self.head_limit.saturating_sub(self.head.len());
        let head_take = remaining_head.min(chunk.len());
        if head_take > 0 {
            self.head.extend_from_slice(&chunk[..head_take]);
        }
        let remainder = &chunk[head_take..];
        let tail_limit = self.limit.saturating_sub(self.head_limit);
        if tail_limit == 0 || remainder.is_empty() {
            return;
        }
        self.tail.extend_from_slice(remainder);
        if self.tail.len() > tail_limit {
            let overflow = self.tail.len() - tail_limit;
            self.tail.drain(..overflow);
        }
    }

    #[must_use]
    pub fn payload(&self) -> CapturePayload {
        let mut retained = Vec::with_capacity(self.head.len() + self.tail.len());
        retained.extend_from_slice(&self.head);
        retained.extend_from_slice(&self.tail);
        let retained_bytes = retained.len();
        CapturePayload {
            text: String::from_utf8_lossy(&retained).into_owned(),
            total_bytes: self.total_bytes,
            retained_bytes,
            dropped_bytes: self.total_bytes.saturating_sub(retained_bytes),
            truncated: self.total_bytes > retained_bytes,
        }
    }

    #[must_use]
    pub fn head(&self) -> &[u8] {
        &self.head
    }

    #[must_use]
    pub fn tail(&self) -> &[u8] {
        &self.tail
    }

    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    #[must_use]
    pub fn tail_start_offset(&self) -> usize {
        self.total_bytes.saturating_sub(self.tail.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_head_and_rolling_tail() {
        let mut capture = BoundedCapture::new(10, 4);
        capture.append(b"abcdefghijklmno");
        let payload = capture.payload();
        assert_eq!(payload.text, "abcdjklmno");
        assert_eq!(payload.total_bytes, 15);
        assert_eq!(payload.retained_bytes, 10);
        assert_eq!(payload.dropped_bytes, 5);
        assert!(payload.truncated);
        assert_eq!(capture.tail_start_offset(), 9);
    }
}
