use crate::ports::random_source::RandomSource;

const EPHEMERAL_BASE: u16 = 49152;
const EPHEMERAL_MASK: u32 = 0x3FFF;

pub fn stealth_udp_port(random: &dyn RandomSource) -> u16 {
    let mut raw = [0u8; 4];
    random.fill_bytes(&mut raw);
    let offset = (u32::from_le_bytes(raw) & EPHEMERAL_MASK) as u16;
    EPHEMERAL_BASE + offset
}
