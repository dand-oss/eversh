//! Per-QUIC-stream diagnostic offsets, independent of association sequence.

#[derive(Debug)]
pub(crate) struct Cursor {
    next: Option<u64>,
}

impl Default for Cursor {
    fn default() -> Self {
        Self { next: Some(0) }
    }
}

impl Cursor {
    /// Reserve once when a complete wire record becomes the pending write.
    /// Partial writes and blocked retries retain that reservation. A new QUIC
    /// stream gets a new cursor even when replay uses old association sequences.
    pub(crate) fn reserve(&mut self, bytes: usize) -> Option<(u64, u64)> {
        let start = self.next.take()?;
        let len = u64::try_from(bytes).ok().filter(|len| *len > 0)?;
        self.next = start.checked_add(len);
        self.next.map(|_| (start, len))
    }
}

#[cfg(test)]
mod tests {
    use super::Cursor;

    #[test]
    fn variable_operations_include_headers_and_resume_starts_at_zero() {
        let mut cursor = Cursor::default();
        assert_eq!(cursor.reserve(15), Some((0, 15)));
        assert_eq!(cursor.reserve(22), Some((15, 22)));
        assert_eq!(cursor.reserve(14), Some((37, 14)));
        let mut replacement_stream = Cursor::default();
        assert_eq!(replacement_stream.reserve(22), Some((0, 22)));
    }

    #[test]
    fn overflow_or_empty_reservation_permanently_invalidates_cursor() {
        let mut cursor = Cursor {
            next: Some(u64::MAX - 1),
        };
        assert_eq!(cursor.reserve(2), None);
        assert_eq!(cursor.reserve(1), None);
        let mut cursor = Cursor::default();
        assert_eq!(cursor.reserve(0), None);
        assert_eq!(cursor.reserve(1), None);
    }
}
