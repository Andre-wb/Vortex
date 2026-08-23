pub mod call_index_conformance;
pub mod call_records_conformance;
pub mod recording_marks_conformance;
pub mod ring_claims_conformance;
pub mod stage_board_conformance;
pub mod stream_donations_conformance;
pub mod stream_hands_conformance;
pub mod stream_records_conformance;
pub mod stream_roster_conformance;
pub mod stream_schedule_conformance;
pub mod stream_tally_conformance;
pub mod voice_presence_conformance;

pub const BASE: f64 = 1_000.0;
pub const MINUTE: f64 = 60.0;
pub const BLINK_MILLIS: u64 = 1_100;
pub const BLINK: f64 = 1.2;

pub fn until(now: f64) -> f64 {
    now + MINUTE
}

pub fn blink(now: f64) -> f64 {
    now + 1.0
}
