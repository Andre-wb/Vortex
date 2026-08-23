use crate::push::limits;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PushCategory(u8);

impl PushCategory {
    pub fn wrapping(value: i64) -> Self {
        PushCategory(value.rem_euclid(i64::from(limits::CATEGORY_COUNT)) as u8)
    }

    pub fn of(value: u8) -> Self {
        PushCategory(value)
    }

    pub fn value(self) -> u8 {
        self.0
    }

    pub fn written(self) -> String {
        self.0.to_string()
    }

    pub fn every() -> impl Iterator<Item = PushCategory> {
        (0..=u8::MAX).map(PushCategory)
    }
}

#[cfg(test)]
mod tests {
    use super::PushCategory;
    use crate::push::limits;

    #[test]
    fn a_category_inside_the_range_is_kept_as_is() {
        assert_eq!(PushCategory::wrapping(0).value(), 0);
        assert_eq!(PushCategory::wrapping(255).value(), 255);
    }

    #[test]
    fn a_category_past_the_range_wraps_around() {
        assert_eq!(PushCategory::wrapping(256).value(), 0);
        assert_eq!(PushCategory::wrapping(257).value(), 1);
    }

    #[test]
    fn a_negative_category_wraps_the_way_python_wraps_it() {
        assert_eq!(PushCategory::wrapping(-1).value(), 255);
        assert_eq!(PushCategory::wrapping(-256).value(), 0);
    }

    #[test]
    fn every_category_is_named_once() {
        assert_eq!(
            PushCategory::every().count(),
            usize::from(limits::CATEGORY_COUNT)
        );
    }
}
