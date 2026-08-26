//! The bootroot-owned envelope.
//!
//! One connection carries exactly one request and then closes. A request
//! is
//!
//! ```text
//! +----------------+--------------+------------------+-----------------+
//! | payload length | name length  | operation name   | payload         |
//! | 4 bytes, BE    | 1 byte       | 1..=32 bytes     | payload length  |
//! +----------------+--------------+------------------+-----------------+
//! ```
//!
//! and a response is a four-byte big-endian length followed by that many
//! bytes. A zero-length payload is valid in both directions.
//!
//! There is no protocol version, magic number, capability list or status
//! field, and that is a decision rather than an omission. Versioning
//! belongs to the payload, which is the protocol sibling's to define; a
//! second version negotiation in the envelope would be a second place
//! for the two ends to disagree. A status field would be a wire error,
//! and this endpoint deliberately answers a pre-verb refusal with a
//! clean close and nothing else — a refused caller learns that it was
//! refused and learns nothing it did not already know about the daemon's
//! internals.

use super::MAX_FRAME_PAYLOAD_BYTES;

/// Bytes of the fixed request prefix: the four-byte payload length and
/// the one-byte operation-name length.
pub(crate) const REQUEST_PREFIX_BYTES: usize = 5;

/// Bytes of the response prefix: the four-byte payload length.
pub(crate) const RESPONSE_PREFIX_BYTES: usize = 4;

/// Longest operation name the envelope admits.
pub(crate) const MAX_OPERATION_NAME_BYTES: usize = 32;

/// The only two operations the endpoint recognizes.
///
/// An enum rather than a string, so the dispatcher matches exhaustively
/// and a third operation cannot be added by a caller, only by a compiler
/// error somebody has to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operation {
    /// Mint — or idempotently re-mint — one service identity.
    Mint,
    /// Tear one service identity down.
    Deregister,
}

impl Operation {
    /// Recognizes a syntactically valid operation name.
    ///
    /// Only ever called with a name that already passed
    /// [`check_operation_name`], so an unrecognized name here is a real
    /// unknown operation rather than a malformed one.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "mint" => Some(Self::Mint),
            "deregister" => Some(Self::Deregister),
            _ => None,
        }
    }

    /// Returns the wire name.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Deregister => "deregister",
        }
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why an operation-name field is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MalformedNameCause {
    /// The declared length was zero, so there is no name at all.
    EmptyName,
    /// The declared length exceeded [`MAX_OPERATION_NAME_BYTES`].
    NameTooLong {
        /// The declared length.
        declared: u8,
    },
    /// A byte outside `[a-z_]` appeared in the name.
    NonNameByte,
}

impl std::fmt::Display for MalformedNameCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyName => f.write_str("zero-length operation name"),
            Self::NameTooLong { declared } => write!(
                f,
                "operation name length {declared} exceeds {MAX_OPERATION_NAME_BYTES}"
            ),
            Self::NonNameByte => f.write_str("operation name contains a byte outside [a-z_]"),
        }
    }
}

/// Checks the declared operation-name length, before a byte of it is
/// read.
///
/// # Errors
///
/// Returns the cause for a zero or over-long declaration.
pub(crate) fn check_operation_name_length(declared: u8) -> Result<usize, MalformedNameCause> {
    if declared == 0 {
        return Err(MalformedNameCause::EmptyName);
    }
    let length = usize::from(declared);
    if length > MAX_OPERATION_NAME_BYTES {
        return Err(MalformedNameCause::NameTooLong { declared });
    }
    Ok(length)
}

/// Checks the operation-name bytes themselves.
///
/// The alphabet is exactly `[a-z_]`: no digits, no hyphens, no
/// uppercase, so there is one spelling of every name and no
/// case-folding rule to get wrong.
///
/// # Errors
///
/// Returns [`MalformedNameCause::NonNameByte`] for any byte outside the
/// alphabet.
pub(crate) fn check_operation_name(bytes: &[u8]) -> Result<&str, MalformedNameCause> {
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || *byte == b'_')
    {
        return Err(MalformedNameCause::NonNameByte);
    }
    // Every byte is ASCII, so the slice is UTF-8 by construction.
    std::str::from_utf8(bytes).map_err(|_| MalformedNameCause::NonNameByte)
}

/// Renders name bytes for a log line: printable ASCII verbatim,
/// everything else as `\xNN`, and never more than
/// [`MAX_OPERATION_NAME_BYTES`] source bytes.
///
/// Caller-supplied bytes reach a log through this function and no other.
/// The cap matches the envelope's own limit, so an over-long declaration
/// that was refused before its bytes were read cannot be used to write
/// an unbounded line either.
pub(crate) fn escape_name_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let shown = bytes.get(..MAX_OPERATION_NAME_BYTES).unwrap_or(bytes);
    let mut out = String::with_capacity(shown.len());
    for byte in shown {
        if byte.is_ascii_graphic() && *byte != b'\\' {
            out.push(char::from(*byte));
        } else {
            let _ = write!(out, "\\x{byte:02x}");
        }
    }
    if shown.len() < bytes.len() {
        out.push_str("...");
    }
    out
}

/// Reads the four-byte big-endian payload length out of a request
/// prefix.
pub(crate) fn declared_payload_length(prefix: [u8; REQUEST_PREFIX_BYTES]) -> u32 {
    u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]])
}

/// Reads the one-byte operation-name length out of a request prefix.
pub(crate) fn declared_name_length(prefix: [u8; REQUEST_PREFIX_BYTES]) -> u8 {
    prefix[4]
}

/// Why a request envelope could not be composed.
///
/// The caller's half of the envelope has exactly one way to fail that
/// the layout above does not already rule out: a payload the four-byte
/// length field could carry and this endpoint's bound will not accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("request payload is {length} bytes, over the {limit}-byte maximum")]
pub(crate) struct OverLongRequestPayload {
    /// Length of the payload that was offered.
    pub(crate) length: usize,
    /// The bound it broke, which is [`MAX_FRAME_PAYLOAD_BYTES`].
    pub(crate) limit: usize,
}

/// Composes the request envelope around an already-encoded payload.
///
/// The caller's half of the layout this module owns, so a client writes
/// the prefix through this function rather than restating the field
/// order and the length arithmetic beside its socket.
///
/// # Errors
///
/// Returns [`OverLongRequestPayload`] when `payload` exceeds
/// [`MAX_FRAME_PAYLOAD_BYTES`]. The endpoint would refuse such a frame
/// with a bare close, so refusing it here costs a caller nothing and
/// tells it why.
pub(crate) fn encode_request_frame(
    operation: Operation,
    payload: &[u8],
) -> Result<Vec<u8>, OverLongRequestPayload> {
    if payload.len() > MAX_FRAME_PAYLOAD_BYTES {
        return Err(OverLongRequestPayload {
            length: payload.len(),
            limit: MAX_FRAME_PAYLOAD_BYTES,
        });
    }
    let payload_length = u32::try_from(payload.len())
        .expect("the length was just checked against MAX_FRAME_PAYLOAD_BYTES, which fits a u32");
    let name = operation.as_str().as_bytes();
    let name_length = u8::try_from(name.len())
        .expect("every Operation name is at most MAX_OPERATION_NAME_BYTES long, which fits a u8");

    let mut frame = Vec::with_capacity(REQUEST_PREFIX_BYTES + name.len() + payload.len());
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.push(name_length);
    frame.extend_from_slice(name);
    frame.extend_from_slice(payload);
    Ok(frame)
}
