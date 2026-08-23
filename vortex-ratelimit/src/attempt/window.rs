#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Window(u64);

impl Window {
    pub fn seconds(value: u64) -> Option<Self> {
        if value == 0 {
            return None;
        }
        Some(Window(value))
    }

    pub fn as_seconds(self) -> u64 {
        self.0
    }

    pub fn width(self) -> f64 {
        self.0 as f64
    }
}

#[cfg(test)]
mod tests {
    use super::Window;

    #[test]
    fn a_window_is_as_wide_as_it_was_given() {
        let window = Window::seconds(60).unwrap();
        assert_eq!(window.as_seconds(), 60);
        assert_eq!(window.width(), 60.0);
    }

    #[test]
    fn a_window_of_zero_width_holds_nothing_and_does_not_exist() {
        assert!(Window::seconds(0).is_none());
        assert!(Window::seconds(1).is_some());
    }
}
