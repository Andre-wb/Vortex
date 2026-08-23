use crate::stream::record::Stream;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StreamPatch {
    pub title: Option<String>,
    pub description: Option<String>,
    pub allow_reactions: Option<bool>,
    pub allow_donations: Option<bool>,
    pub donation_card: Option<String>,
    pub donation_message: Option<String>,
    pub auto_accept_speakers: Option<bool>,
}

impl StreamPatch {
    pub fn applied(&self, stream: &Stream, until: f64) -> Stream {
        let mut changed = stream.clone();
        if let Some(value) = &self.title {
            changed.title = value.clone();
        }
        if let Some(value) = &self.description {
            changed.description = value.clone();
        }
        if let Some(value) = self.allow_reactions {
            changed.allow_reactions = value;
        }
        if let Some(value) = self.allow_donations {
            changed.allow_donations = value;
        }
        if let Some(value) = &self.donation_card {
            changed.donation_card = value.clone();
        }
        if let Some(value) = &self.donation_message {
            changed.donation_message = value.clone();
        }
        if let Some(value) = self.auto_accept_speakers {
            changed.auto_accept_speakers = value;
        }
        changed.until = until;
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::StreamPatch;
    use crate::stream::record::tests::stream;

    #[test]
    fn a_patch_that_names_nothing_changes_only_the_moment_it_expires() {
        let before = stream();
        let after = StreamPatch::default().applied(&before, 1_240.0);
        assert_eq!(after.title, before.title);
        assert_eq!(after.allow_reactions, before.allow_reactions);
        assert_eq!(after.until, 1_240.0);
    }

    #[test]
    fn a_patch_changes_only_what_it_names() {
        let patch = StreamPatch {
            title: Some("Другой".to_owned()),
            allow_donations: Some(true),
            ..StreamPatch::default()
        };
        let after = patch.applied(&stream(), 1_240.0);
        assert_eq!(after.title, "Другой");
        assert!(after.allow_donations);
        assert_eq!(after.description, stream().description);
    }

    #[test]
    fn an_empty_title_in_a_patch_is_kept_as_the_host_typed_it() {
        let patch = StreamPatch {
            title: Some(String::new()),
            ..StreamPatch::default()
        };
        assert_eq!(patch.applied(&stream(), 1_240.0).title, "");
    }
}
