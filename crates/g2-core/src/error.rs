use std::path::PathBuf;

/// Errors produced while loading or validating gateway configuration.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An API definition failed semantic validation.
    #[error("invalid API definition `{api}`: {reason}")]
    InvalidApiDefinition {
        /// The `api_id` (or file name, if the id is unknown) of the offending definition.
        api: String,
        /// Human-readable description of what is wrong.
        reason: String,
    },

    /// A key session failed semantic validation.
    ///
    /// Sessions carry no natural identifier of their own (they are addressed
    /// by key hash), so the error carries only the reason.
    #[error("invalid key session: {reason}")]
    InvalidKeySession {
        /// Human-readable description of what is wrong.
        reason: String,
    },

    /// Two API definitions collide (same `api_id` or same `listen_path`).
    #[error("conflicting API definitions: {reason}")]
    ConflictingApiDefinitions {
        /// Human-readable description of the collision.
        reason: String,
    },

    /// A definition or config file could not be read.
    #[error("failed to read {path}: {source}")]
    Io {
        /// Path of the file or directory that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A definition or config file could not be parsed.
    #[error("failed to parse {path}: {reason}")]
    Parse {
        /// Path of the file that could not be parsed.
        path: PathBuf,
        /// Parser error message.
        reason: String,
    },
}
