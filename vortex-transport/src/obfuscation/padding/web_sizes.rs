pub const WEB_SIZES: [usize; 8] = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768];

#[cfg(test)]
mod tests {
    use super::WEB_SIZES;

    #[test]
    fn the_sizes_grow_and_never_repeat() {
        assert!(WEB_SIZES.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
