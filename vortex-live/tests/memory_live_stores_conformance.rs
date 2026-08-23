use std::sync::Arc;

use vortex_live::call::memory::{MemoryCallIndex, MemoryCallRecords, MemoryRingClaims};
use vortex_live::ports::call_index::CallIndex;
use vortex_live::ports::call_records::CallRecords;
use vortex_live::ports::recording_marks::RecordingMarks;
use vortex_live::ports::ring_claims::RingClaims;
use vortex_live::ports::stage_board::StageBoard;
use vortex_live::ports::stream_donations::StreamDonations;
use vortex_live::ports::stream_hands::StreamHands;
use vortex_live::ports::stream_records::StreamRecords;
use vortex_live::ports::stream_roster::StreamRoster;
use vortex_live::ports::stream_schedule::StreamSchedule;
use vortex_live::ports::stream_tally::StreamTally;
use vortex_live::ports::voice_presence::VoicePresence;
use vortex_live::recording::memory::MemoryRecordingMarks;
use vortex_live::stage::memory::MemoryStageBoard;
use vortex_live::stream::memory::{
    MemoryStreamDonations, MemoryStreamHands, MemoryStreamRecords, MemoryStreamRoster,
    MemoryStreamTally,
};
use vortex_live::stream::schedule::memory::MemoryStreamSchedule;
use vortex_live::testing::{
    call_index_conformance, call_records_conformance, recording_marks_conformance,
    ring_claims_conformance, stage_board_conformance, stream_donations_conformance,
    stream_hands_conformance, stream_records_conformance, stream_roster_conformance,
    stream_schedule_conformance, stream_tally_conformance, voice_presence_conformance,
};
use vortex_live::voice::memory::MemoryVoicePresence;

#[test]
fn voice_presence_in_memory_satisfies_the_port_contract() {
    let make = || -> Arc<dyn VoicePresence> { Arc::new(MemoryVoicePresence::new()) };
    voice_presence_conformance::check_all(&make);
}

#[test]
fn the_stage_board_in_memory_satisfies_the_port_contract() {
    let make = || -> Arc<dyn StageBoard> { Arc::new(MemoryStageBoard::new()) };
    stage_board_conformance::check_all(&make);
}

#[test]
fn recording_marks_in_memory_satisfy_the_port_contract() {
    let make = || -> Arc<dyn RecordingMarks> { Arc::new(MemoryRecordingMarks::new()) };
    recording_marks_conformance::check_all(&make);
}

#[test]
fn call_records_in_memory_satisfy_the_port_contract() {
    let make = || -> Arc<dyn CallRecords> { Arc::new(MemoryCallRecords::new()) };
    call_records_conformance::check_all(&make);
}

#[test]
fn the_call_index_in_memory_satisfies_the_port_contract() {
    let make = || -> Arc<dyn CallIndex> { Arc::new(MemoryCallIndex::new()) };
    call_index_conformance::check_all(&make);
}

#[test]
fn ring_claims_in_memory_satisfy_the_port_contract() {
    let make = || -> Arc<dyn RingClaims> { Arc::new(MemoryRingClaims::new()) };
    ring_claims_conformance::check_all(&make);
}

#[test]
fn stream_records_in_memory_satisfy_the_port_contract() {
    let make = || -> Arc<dyn StreamRecords> { Arc::new(MemoryStreamRecords::new()) };
    stream_records_conformance::check_all(&make);
}

#[test]
fn the_stream_roster_in_memory_satisfies_the_port_contract() {
    let make = || -> Arc<dyn StreamRoster> { Arc::new(MemoryStreamRoster::new()) };
    stream_roster_conformance::check_all(&make);
}

#[test]
fn stream_hands_in_memory_satisfy_the_port_contract() {
    let make = || -> Arc<dyn StreamHands> { Arc::new(MemoryStreamHands::new()) };
    stream_hands_conformance::check_all(&make);
}

#[test]
fn the_stream_tally_in_memory_satisfies_the_port_contract() {
    let make = || -> Arc<dyn StreamTally> { Arc::new(MemoryStreamTally::new()) };
    stream_tally_conformance::check_all(&make);
}

#[test]
fn stream_donations_in_memory_satisfy_the_port_contract() {
    let make = || -> Arc<dyn StreamDonations> { Arc::new(MemoryStreamDonations::new()) };
    stream_donations_conformance::check_all(&make);
}

#[test]
fn the_stream_schedule_in_memory_satisfies_the_port_contract() {
    let make = || -> Arc<dyn StreamSchedule> { Arc::new(MemoryStreamSchedule::new()) };
    stream_schedule_conformance::check_all(&make);
}
