use crate::reality::short_id::value::ShortId;

pub trait ShortIdRegistry: Send + Sync {
    fn contains(&self, short_id: &ShortId) -> bool;

    fn insert(&self, short_id: ShortId) -> bool;

    fn remove(&self, short_id: &ShortId) -> bool;

    fn all(&self) -> Vec<ShortId>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
