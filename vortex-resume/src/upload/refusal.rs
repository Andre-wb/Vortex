use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    EmptyIdentifier,
    OverLongIdentifier,
    IdentifierOutsideAlphabet,
    EmptyFileName,
    OverLongFileName,
    FileNameOutsideAlphabet,
    EmptyFile,
    TooManyChunks { asked: u64 },
}

impl Refusal {
    pub fn message(&self) -> String {
        match self {
            Refusal::EmptyIdentifier => "Upload id is required".to_owned(),
            Refusal::OverLongIdentifier => format!(
                "Upload id longer than {} characters",
                super::limits::MAX_IDENTIFIER_LENGTH
            ),
            Refusal::IdentifierOutsideAlphabet => "Upload id is not url-safe base64".to_owned(),
            Refusal::EmptyFileName => "File name is required".to_owned(),
            Refusal::OverLongFileName => format!(
                "File name longer than {} characters",
                super::limits::MAX_FILE_NAME_LENGTH
            ),
            Refusal::FileNameOutsideAlphabet => "File name holds a control character".to_owned(),
            Refusal::EmptyFile => "File size must be positive".to_owned(),
            Refusal::TooManyChunks { asked } => format!(
                "Too many chunks: {} (maximum {}). Increase chunk_size.",
                asked,
                super::limits::MAX_CHUNKS
            ),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Refusal::EmptyIdentifier => "upload_id_required",
            Refusal::OverLongIdentifier => "upload_id_long",
            Refusal::IdentifierOutsideAlphabet => "upload_id_alphabet",
            Refusal::EmptyFileName => "file_name_required",
            Refusal::OverLongFileName => "file_name_long",
            Refusal::FileNameOutsideAlphabet => "file_name_alphabet",
            Refusal::EmptyFile => "file_size_invalid",
            Refusal::TooManyChunks { .. } => "too_many_chunks",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for Refusal {}

#[cfg(test)]
mod tests {
    use super::Refusal;

    const EVERY: [Refusal; 8] = [
        Refusal::EmptyIdentifier,
        Refusal::OverLongIdentifier,
        Refusal::IdentifierOutsideAlphabet,
        Refusal::EmptyFileName,
        Refusal::OverLongFileName,
        Refusal::FileNameOutsideAlphabet,
        Refusal::EmptyFile,
        Refusal::TooManyChunks { asked: 0 },
    ];

    #[test]
    fn every_refusal_can_be_told_to_a_client() {
        for refusal in EVERY {
            assert!(!refusal.message().is_empty());
            assert!(refusal.message().is_ascii());
            assert!(!refusal.code().is_empty());
        }
    }

    #[test]
    fn a_refusal_names_the_limit_it_enforced() {
        assert_eq!(
            Refusal::TooManyChunks { asked: 20000 }.message(),
            "Too many chunks: 20000 (maximum 10240). Increase chunk_size."
        );
    }
}
