//! Resize ownership without parsing terminal bytes or keeping screen state.
use crate::wire::Resize;
use crate::{InputOperation, QueueError};
use everssh::association::AssociationId;

#[derive(Clone, Copy)]
struct WriterSize {
    id: AssociationId,
    size: Option<Resize>,
}

pub(crate) struct WriterSizes {
    writers: [Option<WriterSize>; 9],
    owner: Option<AssociationId>,
    ever_owned: bool,
    applied: Option<(u16, u16)>,
}

pub(crate) struct SizeAction {
    pub deliver: bool,
    pub before_input: Option<Resize>,
}

impl WriterSizes {
    pub fn new() -> Self {
        Self {
            writers: [None; 9],
            owner: None,
            ever_owned: false,
            applied: None,
        }
    }

    pub fn initial_dimensions(&mut self, rows: u16, columns: u16) {
        if rows != 0 && columns != 0 {
            self.applied = Some((rows, columns));
        }
    }

    pub fn add(&mut self, id: AssociationId) -> Result<(), QueueError> {
        if self.writers.iter().flatten().any(|writer| writer.id == id) {
            return Ok(());
        }
        let slot = self
            .writers
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(QueueError::ObserverCapacity)?;
        *slot = Some(WriterSize { id, size: None });
        if !self.ever_owned {
            self.owner = Some(id);
            self.ever_owned = true;
        }
        Ok(())
    }

    pub fn remove(&mut self, id: AssociationId) {
        for slot in &mut self.writers {
            if slot.is_some_and(|writer| writer.id == id) {
                *slot = None;
            }
        }
        if self.owner == Some(id) {
            self.owner = None;
        }
        // Retain the actual PTY dimensions until another writer types.
    }

    pub fn take_over(&mut self, id: AssociationId) {
        self.owner = Some(id);
        self.ever_owned = true;
    }

    fn changed(&mut self, size: Resize) -> Option<Resize> {
        let dimensions = (size.rows, size.columns);
        if self.applied == Some(dimensions) {
            return None;
        }
        self.applied = Some(dimensions);
        Some(size)
    }

    pub fn operation(
        &mut self,
        id: AssociationId,
        operation: InputOperation<'_>,
    ) -> Result<SizeAction, QueueError> {
        let writer = self
            .writers
            .iter_mut()
            .flatten()
            .find(|writer| writer.id == id)
            .ok_or(QueueError::UnknownObserver)?;
        match operation {
            InputOperation::Resize(size) => {
                writer.size = Some(size);
                let deliver = self.owner == Some(id) && self.changed(size).is_some();
                Ok(SizeAction {
                    deliver,
                    before_input: None,
                })
            }
            InputOperation::Bytes(bytes) if !bytes.is_empty() => {
                let size = writer.size;
                self.owner = Some(id);
                let before_input = size.and_then(|size| self.changed(size));
                Ok(SizeAction {
                    deliver: true,
                    before_input,
                })
            }
            _ => Ok(SizeAction {
                deliver: true,
                before_input: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: u8) -> AssociationId {
        AssociationId::from_bytes([n; 16]).expect("id")
    }
    fn size(rows: u16, columns: u16) -> Resize {
        Resize {
            rows,
            columns,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
    #[test]
    fn only_active_writer_resizes_and_joins_do_not_steal() {
        let mut sizes = WriterSizes::new();
        sizes.initial_dimensions(24, 80);
        sizes.add(id(1)).expect("first");
        assert!(
            !sizes
                .operation(id(1), InputOperation::Resize(size(24, 80)))
                .expect("same")
                .deliver
        );
        sizes.add(id(2)).expect("second");
        assert!(
            !sizes
                .operation(id(2), InputOperation::Resize(size(40, 120)))
                .expect("store")
                .deliver
        );
        assert!(sizes
            .operation(id(2), InputOperation::Bytes(b""))
            .expect("empty")
            .before_input
            .is_none());
        assert_eq!(sizes.owner, Some(id(1)));
        assert_eq!(
            sizes
                .operation(id(2), InputOperation::Bytes(b"x"))
                .expect("type")
                .before_input,
            Some(size(40, 120))
        );
        assert!(
            !sizes
                .operation(id(1), InputOperation::Resize(size(30, 100)))
                .expect("inactive")
                .deliver
        );
        assert!(
            sizes
                .operation(id(2), InputOperation::Resize(size(41, 121)))
                .expect("owner")
                .deliver
        );
        assert_eq!(
            sizes
                .operation(id(1), InputOperation::Bytes(b"y"))
                .expect("switch")
                .before_input,
            Some(size(30, 100))
        );
        sizes.remove(id(1));
        assert_eq!(sizes.applied, Some((30, 100)));
        assert!(
            !sizes
                .operation(id(2), InputOperation::Resize(size(42, 122)))
                .expect("no owner")
                .deliver
        );
        sizes.take_over(id(2));
        assert!(
            sizes
                .operation(id(2), InputOperation::Resize(size(42, 122)))
                .expect("takeover")
                .deliver
        );
    }
}
