use std::sync::Arc;

use vortex_live::call::memory::{MemoryCallIndex, MemoryCallRecords, MemoryRingClaims};
use vortex_live::call::unavailable::{
    UnavailableCallIndex, UnavailableCallRecords, UnavailableRingClaims,
};
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
use vortex_live::recording::unavailable::UnavailableRecordingMarks;
use vortex_live::stage::memory::MemoryStageBoard;
use vortex_live::stage::unavailable::UnavailableStageBoard;
use vortex_live::stream::memory::{
    MemoryStreamDonations, MemoryStreamHands, MemoryStreamRecords, MemoryStreamRoster,
    MemoryStreamTally,
};
use vortex_live::stream::schedule::memory::MemoryStreamSchedule;
use vortex_live::stream::schedule::unavailable::UnavailableStreamSchedule;
use vortex_live::stream::unavailable::{
    UnavailableStreamDonations, UnavailableStreamHands, UnavailableStreamRecords,
    UnavailableStreamRoster, UnavailableStreamTally,
};
use vortex_live::voice::memory::MemoryVoicePresence;
use vortex_live::voice::unavailable::UnavailableVoicePresence;
use vortex_redis::backbone::RedisBackbone;
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

pub struct Stores {
    pub presence: Arc<dyn VoicePresence>,
    pub stage: Arc<dyn StageBoard>,
    pub recording: Arc<dyn RecordingMarks>,
    pub call_records: Arc<dyn CallRecords>,
    pub call_index: Arc<dyn CallIndex>,
    pub rings: Arc<dyn RingClaims>,
    pub stream_records: Arc<dyn StreamRecords>,
    pub roster: Arc<dyn StreamRoster>,
    pub hands: Arc<dyn StreamHands>,
    pub tally: Arc<dyn StreamTally>,
    pub donations: Arc<dyn StreamDonations>,
    pub schedule: Arc<dyn StreamSchedule>,
}

impl Stores {
    pub fn in_memory() -> Self {
        Stores {
            presence: Arc::new(MemoryVoicePresence::new()),
            stage: Arc::new(MemoryStageBoard::new()),
            recording: Arc::new(MemoryRecordingMarks::new()),
            call_records: Arc::new(MemoryCallRecords::new()),
            call_index: Arc::new(MemoryCallIndex::new()),
            rings: Arc::new(MemoryRingClaims::new()),
            stream_records: Arc::new(MemoryStreamRecords::new()),
            roster: Arc::new(MemoryStreamRoster::new()),
            hands: Arc::new(MemoryStreamHands::new()),
            tally: Arc::new(MemoryStreamTally::new()),
            donations: Arc::new(MemoryStreamDonations::new()),
            schedule: Arc::new(MemoryStreamSchedule::new()),
        }
    }

    pub fn sealed() -> Self {
        Stores {
            presence: Arc::new(UnavailableVoicePresence::new()),
            stage: Arc::new(UnavailableStageBoard::new()),
            recording: Arc::new(UnavailableRecordingMarks::new()),
            call_records: Arc::new(UnavailableCallRecords::new()),
            call_index: Arc::new(UnavailableCallIndex::new()),
            rings: Arc::new(UnavailableRingClaims::new()),
            stream_records: Arc::new(UnavailableStreamRecords::new()),
            roster: Arc::new(UnavailableStreamRoster::new()),
            hands: Arc::new(UnavailableStreamHands::new()),
            tally: Arc::new(UnavailableStreamTally::new()),
            donations: Arc::new(UnavailableStreamDonations::new()),
            schedule: Arc::new(UnavailableStreamSchedule::new()),
        }
    }

    pub fn in_redis(backbone: Arc<RedisBackbone>) -> Self {
        Stores {
            presence: Arc::new(RedisVoicePresence::new(backbone.clone())),
            stage: Arc::new(RedisStageBoard::new(backbone.clone())),
            recording: Arc::new(RedisRecordingMarks::new(backbone.clone())),
            call_records: Arc::new(RedisCallRecords::new(backbone.clone())),
            call_index: Arc::new(RedisCallIndex::new(backbone.clone())),
            rings: Arc::new(RedisRingClaims::new(backbone.clone())),
            stream_records: Arc::new(RedisStreamRecords::new(backbone.clone())),
            roster: Arc::new(RedisStreamRoster::new(backbone.clone())),
            hands: Arc::new(RedisStreamHands::new(backbone.clone())),
            tally: Arc::new(RedisStreamTally::new(backbone.clone())),
            donations: Arc::new(RedisStreamDonations::new(backbone.clone())),
            schedule: Arc::new(RedisStreamSchedule::new(backbone)),
        }
    }
}
