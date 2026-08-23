use serde_json::{json, Value};

use crate::stage::record::Stage;

#[derive(Debug, Clone, PartialEq)]
pub struct StageStatus {
    stage: Option<Stage>,
}

impl StageStatus {
    pub fn of(stage: Option<Stage>) -> Self {
        StageStatus { stage }
    }

    pub fn open(&self) -> bool {
        self.stage.is_some()
    }

    pub fn speakers(&self) -> Vec<i64> {
        self.stage
            .as_ref()
            .map(|stage| stage.speakers.clone())
            .unwrap_or_default()
    }

    pub fn speaks(&self, user_id: i64) -> bool {
        match &self.stage {
            Some(stage) => stage.speaks(user_id),
            None => true,
        }
    }

    pub fn view(&self, user_id: i64) -> Value {
        json!({
            "stage_mode": self.open(),
            "speakers": self.speakers(),
            "is_speaker": self.speaks(user_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::StageStatus;
    use crate::stage::record::Stage;
    use serde_json::json;

    #[test]
    fn without_a_stage_everyone_may_speak() {
        let status = StageStatus::of(None);
        assert!(!status.open());
        assert!(status.speaks(7));
        assert_eq!(
            status.view(7),
            json!({"stage_mode": false, "speakers": [], "is_speaker": true})
        );
    }

    #[test]
    fn with_a_stage_only_the_named_speakers_may_speak() {
        let status = StageStatus::of(Some(Stage::opened_by(7, 1_120.0)));
        assert!(status.open());
        assert!(status.speaks(7));
        assert!(!status.speaks(8));
        assert_eq!(
            status.view(8),
            json!({"stage_mode": true, "speakers": [7], "is_speaker": false})
        );
    }
}
