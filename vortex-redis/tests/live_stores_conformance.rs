mod support;

use std::sync::Arc;

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
use vortex_live::testing::{
    call_index_conformance, call_records_conformance, recording_marks_conformance,
    ring_claims_conformance, stage_board_conformance, stream_donations_conformance,
    stream_hands_conformance, stream_records_conformance, stream_roster_conformance,
    stream_schedule_conformance, stream_tally_conformance, voice_presence_conformance,
};
use vortex_redis::live::call_index::RedisCallIndex;
use vortex_redis::live::call_records::RedisCallRecords;
use vortex_redis::live::recording_marks::RedisRecordingMarks;
use vortex_redis::live::ring_claims::RedisRingClaims;
use vortex_redis::live::stage_board::RedisStageBoard;
use vortex_redis::live::stream_donations::RedisStreamDonations;
use vortex_redis::live::stream_hands::RedisStreamHands;
use vortex_redis::live::stream_records::RedisStreamRecords;
use vortex_redis::live::stream_roster::RedisStreamRoster;
use vortex_redis::live::stream_schedule::RedisStreamSchedule;
use vortex_redis::live::stream_tally::RedisStreamTally;
use vortex_redis::live::voice_presence::RedisVoicePresence;

fn reachable(suite: &str) -> bool {
    if support::backbone(&support::unique_prefix(suite)).is_some() {
        return true;
    }
    eprintln!("Redis недоступен — проверка {suite} пропущена");
    false
}

#[test]
fn the_redis_voice_presence_satisfies_the_same_port_contract() {
    if !reachable("voice-presence") {
        return;
    }
    let make = || -> Arc<dyn VoicePresence> {
        let prefix = support::unique_prefix("voice-presence");
        Arc::new(RedisVoicePresence::new(support::backbone(&prefix).unwrap()))
    };
    voice_presence_conformance::check_all(&make);
}

#[test]
fn the_redis_stage_board_satisfies_the_same_port_contract() {
    if !reachable("stage-board") {
        return;
    }
    let make = || -> Arc<dyn StageBoard> {
        let prefix = support::unique_prefix("stage-board");
        Arc::new(RedisStageBoard::new(support::backbone(&prefix).unwrap()))
    };
    stage_board_conformance::check_all(&make);
}

#[test]
fn the_redis_recording_marks_satisfy_the_same_port_contract() {
    if !reachable("recording-marks") {
        return;
    }
    let make = || -> Arc<dyn RecordingMarks> {
        let prefix = support::unique_prefix("recording-marks");
        Arc::new(RedisRecordingMarks::new(
            support::backbone(&prefix).unwrap(),
        ))
    };
    recording_marks_conformance::check_all(&make);
}

#[test]
fn the_redis_call_records_satisfy_the_same_port_contract() {
    if !reachable("call-records") {
        return;
    }
    let make = || -> Arc<dyn CallRecords> {
        let prefix = support::unique_prefix("call-records");
        Arc::new(RedisCallRecords::new(support::backbone(&prefix).unwrap()))
    };
    call_records_conformance::check_all(&make);
}

#[test]
fn the_redis_call_index_satisfies_the_same_port_contract() {
    if !reachable("call-index") {
        return;
    }
    let make = || -> Arc<dyn CallIndex> {
        let prefix = support::unique_prefix("call-index");
        Arc::new(RedisCallIndex::new(support::backbone(&prefix).unwrap()))
    };
    call_index_conformance::check_all(&make);
}

#[test]
fn the_redis_ring_claims_satisfy_the_same_port_contract() {
    if !reachable("ring-claims") {
        return;
    }
    let make = || -> Arc<dyn RingClaims> {
        let prefix = support::unique_prefix("ring-claims");
        Arc::new(RedisRingClaims::new(support::backbone(&prefix).unwrap()))
    };
    ring_claims_conformance::check_all(&make);
}

#[test]
fn the_redis_stream_records_satisfy_the_same_port_contract() {
    if !reachable("stream-records") {
        return;
    }
    let make = || -> Arc<dyn StreamRecords> {
        let prefix = support::unique_prefix("stream-records");
        Arc::new(RedisStreamRecords::new(support::backbone(&prefix).unwrap()))
    };
    stream_records_conformance::check_all(&make);
}

#[test]
fn the_redis_stream_roster_satisfies_the_same_port_contract() {
    if !reachable("stream-roster") {
        return;
    }
    let make = || -> Arc<dyn StreamRoster> {
        let prefix = support::unique_prefix("stream-roster");
        Arc::new(RedisStreamRoster::new(support::backbone(&prefix).unwrap()))
    };
    stream_roster_conformance::check_all(&make);
}

#[test]
fn the_redis_stream_hands_satisfy_the_same_port_contract() {
    if !reachable("stream-hands") {
        return;
    }
    let make = || -> Arc<dyn StreamHands> {
        let prefix = support::unique_prefix("stream-hands");
        Arc::new(RedisStreamHands::new(support::backbone(&prefix).unwrap()))
    };
    stream_hands_conformance::check_all(&make);
}

#[test]
fn the_redis_stream_tally_satisfies_the_same_port_contract() {
    if !reachable("stream-tally") {
        return;
    }
    let make = || -> Arc<dyn StreamTally> {
        let prefix = support::unique_prefix("stream-tally");
        Arc::new(RedisStreamTally::new(support::backbone(&prefix).unwrap()))
    };
    stream_tally_conformance::check_all(&make);
}

#[test]
fn the_redis_stream_donations_satisfy_the_same_port_contract() {
    if !reachable("stream-donations") {
        return;
    }
    let make = || -> Arc<dyn StreamDonations> {
        let prefix = support::unique_prefix("stream-donations");
        Arc::new(RedisStreamDonations::new(
            support::backbone(&prefix).unwrap(),
        ))
    };
    stream_donations_conformance::check_all(&make);
}

#[test]
fn the_redis_stream_schedule_satisfies_the_same_port_contract() {
    if !reachable("stream-schedule") {
        return;
    }
    let make = || -> Arc<dyn StreamSchedule> {
        let prefix = support::unique_prefix("stream-schedule");
        Arc::new(RedisStreamSchedule::new(
            support::backbone(&prefix).unwrap(),
        ))
    };
    stream_schedule_conformance::check_all(&make);
}
