#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    tokens: usize,
    categories: usize,
    wakes: u64,
}

impl Tally {
    pub fn of(tokens: usize, categories: usize, wakes: u64) -> Self {
        Tally {
            tokens,
            categories,
            wakes,
        }
    }

    pub fn tokens(self) -> usize {
        self.tokens
    }

    pub fn categories(self) -> usize {
        self.categories
    }

    pub fn wakes(self) -> u64 {
        self.wakes
    }
}
