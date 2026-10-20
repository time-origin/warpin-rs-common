//! Owned transport bytes for consumers that authenticate records before parsing.
use rdkafka::message::{Headers, Message};

/// An owned Kafka record with no UTF-8 conversion or header normalization.
///
/// `None` (including a tombstone) is distinct from an empty value. Header order,
/// duplicate names and null values are retained exactly as delivered. The topic,
/// partition and offset identify the original broker record; processing and
/// offset-commit policy remain the caller's responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedRawMessage {
    pub topic: String,
    pub partition: i32,
    pub offset: i64,
    pub key: Option<Vec<u8>>,
    pub payload: Option<Vec<u8>>,
    pub headers: Vec<(String, Option<Vec<u8>>)>,
}

impl OwnedRawMessage {
    pub(crate) fn from_message(message: &impl Message) -> Self {
        Self {
            topic: message.topic().to_owned(),
            partition: message.partition(),
            offset: message.offset(),
            key: message.key().map(<[u8]>::to_vec),
            payload: message.payload().map(<[u8]>::to_vec),
            headers: message.headers().map_or_else(Vec::new, |headers| {
                headers
                    .iter()
                    .map(|header| (header.key.to_owned(), header.value.map(<[u8]>::to_vec)))
                    .collect()
            }),
        }
    }
}

#[cfg(test)]
mod tests;
