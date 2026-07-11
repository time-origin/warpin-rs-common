//! Rotation-aware Ed25519 authentication for durable event transport records.
//!
//! The attestation authenticates transport coordinates and bytes. Consumers
//! must call [`ProducerAttestationVerifier::verify`] with raw Kafka topic, key,
//! payload, and headers before parsing the payload. Only the producer, event,
//! and tenant identity in [`VerifiedProducerAttestation`] is authenticated;
//! matching fields in the payload remain claims to compare after verification.
//!
//! Replay protection remains the consumer's responsibility. Persist and
//! deduplicate the verified event ID in an inbox scoped by the verified tenant
//! before committing the source offset. Signature failures are authentication
//! failures. Clock-policy errors such as an expired attestation are returned
//! only after a valid signature authenticates the timestamps.
//!
//! Producers retain their Ed25519 private keys. Consumers receive public keys
//! only and should configure overlapping old and new key IDs for the bounded
//! rotation window.

use std::collections::{HashMap, hash_map::Entry};
use std::fmt;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{DurableEventHeader, DurableEventRecord};

const DOMAIN_SEPARATOR: &[u8] = b"warpin.durable-event-attestation.v1";
const ATTESTATION_VERSION: &[u8] = b"1";

const HEADER_VERSION: &str = "x-warpin-attestation-version";
const HEADER_PRODUCER_SERVICE: &str = "x-warpin-producer-service";
const HEADER_TENANT_ID: &str = "x-warpin-tenant-id";
const HEADER_SIGNING_KEY_ID: &str = "x-warpin-signing-key-id";
const HEADER_EVENT_ID: &str = "x-warpin-event-id";
const HEADER_ISSUED_AT_MS: &str = "x-warpin-issued-at-ms";
const HEADER_EXPIRES_AT_MS: &str = "x-warpin-expires-at-ms";
const HEADER_SIGNATURE: &str = "x-warpin-signature-ed25519";

const RESERVED_HEADERS: [&str; 8] = [
    HEADER_VERSION,
    HEADER_PRODUCER_SERVICE,
    HEADER_TENANT_ID,
    HEADER_SIGNING_KEY_ID,
    HEADER_EVENT_ID,
    HEADER_ISSUED_AT_MS,
    HEADER_EXPIRES_AT_MS,
    HEADER_SIGNATURE,
];

const MAX_PRODUCER_SERVICE_BYTES: usize = 128;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_EVENT_ID_BYTES: usize = 256;
const ED25519_PRIVATE_KEY_BYTES: usize = 32;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;
const ED25519_SIGNATURE_HEX_BYTES: usize = ED25519_SIGNATURE_BYTES * 2;

/// Invalid signer, verifier, or outbound attestation configuration.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum AttestationConfigurationError {
    #[error("producer service identifier is invalid")]
    InvalidProducerService,
    #[error("signing key identifier is invalid")]
    InvalidKeyId,
    #[error("event identifier is invalid")]
    InvalidEventId,
    #[error("private Ed25519 signing key length is invalid (expected {expected}, actual {actual})")]
    InvalidPrivateSigningKeyLength { expected: usize, actual: usize },
    #[error(
        "public Ed25519 verifying key length is invalid (expected {expected}, actual {actual})"
    )]
    InvalidPublicVerifyingKeyLength { expected: usize, actual: usize },
    #[error("public Ed25519 verifying key is invalid")]
    InvalidPublicVerifyingKey,
    #[error("verification validity or future-skew window is invalid")]
    InvalidVerificationWindow,
    #[error("attestation issuance or expiry time is invalid")]
    InvalidAttestationTime,
    #[error("verifying key already exists for producer and key identifier")]
    DuplicateVerifyingKey,
    #[error("caller supplied a reserved attestation header")]
    ReservedHeaderCollision,
    #[error("durable event record cannot carry the attestation")]
    InvalidRecord,
}

/// Failure to authenticate an inbound durable event record.
#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum AttestationVerificationError {
    #[error("required producer attestation header is missing")]
    MissingHeader,
    #[error("producer attestation header is duplicated")]
    DuplicateHeader,
    #[error("producer attestation header is invalid")]
    InvalidHeader,
    #[error("producer attestation version is unsupported")]
    UnsupportedVersion,
    #[error("producer is not configured")]
    UnknownProducer,
    #[error("producer signing key is not configured")]
    UnknownKey,
    #[error("durable event transport coordinates or payload are invalid")]
    InvalidTransportInput,
    #[error("attestation was issued too far in the future")]
    IssuedInFuture,
    #[error("attestation has expired")]
    Expired,
    #[error("attestation validity exceeds verifier policy")]
    ValidityTooLong,
    #[error("attestation timestamp range is invalid")]
    InvalidTimeRange,
    #[error("Ed25519 signature encoding is malformed")]
    MalformedSignature,
    #[error("Ed25519 signature does not authenticate this record")]
    SignatureMismatch,
}

/// Identity authenticated by a successful durable-record verification.
///
/// These fields, rather than similarly named payload fields, are the trusted
/// producer, tenant, and event identity. Applications should compare payload
/// metadata with this value only after verification, then tenant-scope and
/// persist `event_id` in their inbox before committing the Kafka offset.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifiedProducerAttestation {
    /// Authenticated service that held the selected producer private key.
    pub producer_service: String,
    /// Authenticated public-key identifier used for this signature.
    pub key_id: String,
    /// Authenticated event identifier used for tenant-scoped replay dedupe.
    pub event_id: String,
    /// Authenticated tenant used to scope authorization, state, and inbox data.
    pub tenant_id: String,
    /// Authenticated Unix timestamp in milliseconds when the signature began.
    pub issued_at_ms: i64,
    /// Authenticated Unix timestamp in milliseconds when the signature expires.
    pub expires_at_ms: i64,
}

/// Producer-local Ed25519 signer.
///
/// The producer is responsible for loading the private key from its secret
/// store and never distributing it to consumers. Create a new signer with a
/// new key ID during rotation; consumers should retain both public keys until
/// the old validity and broker-backlog windows have elapsed.
///
/// The input seed is wiped immediately after construction. The retained
/// `SigningKey` uses ed25519-dalek's `zeroize` feature and wipes its secret
/// seed on drop. Neither value is included in `Debug` output.
pub struct ProducerAttestationSigner {
    producer_service: String,
    key_id: String,
    signing_key: SigningKey,
}

impl fmt::Debug for ProducerAttestationSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProducerAttestationSigner")
            .field("producer_service", &self.producer_service)
            .field("key_id", &self.key_id)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl ProducerAttestationSigner {
    /// Creates a signer from a producer identity, rotation key ID, and an
    /// exact 32-byte Ed25519 private seed.
    ///
    /// The seed is placed under zeroization before any validation can return.
    /// Producer and key identifiers are safe bounded transport identifiers;
    /// neither is a substitute for protecting the private seed.
    pub fn new(
        producer_service: impl Into<String>,
        key_id: impl Into<String>,
        private_signing_key: Vec<u8>,
    ) -> Result<Self, AttestationConfigurationError> {
        // Wrap at the function boundary so every early return wipes the
        // caller-provided private seed allocation.
        let private_signing_key = Zeroizing::new(private_signing_key);
        let producer_service = producer_service.into();
        let key_id = key_id.into();
        if !valid_identifier(&producer_service, MAX_PRODUCER_SERVICE_BYTES) {
            return Err(AttestationConfigurationError::InvalidProducerService);
        }
        if !valid_identifier(&key_id, MAX_KEY_ID_BYTES) {
            return Err(AttestationConfigurationError::InvalidKeyId);
        }

        if private_signing_key.len() != ED25519_PRIVATE_KEY_BYTES {
            return Err(
                AttestationConfigurationError::InvalidPrivateSigningKeyLength {
                    expected: ED25519_PRIVATE_KEY_BYTES,
                    actual: private_signing_key.len(),
                },
            );
        }
        let mut seed = Zeroizing::new([0_u8; ED25519_PRIVATE_KEY_BYTES]);
        seed.copy_from_slice(private_signing_key.as_slice());
        let signing_key = SigningKey::from_bytes(&seed);

        Ok(Self {
            producer_service,
            key_id,
            signing_key,
        })
    }

    /// Appends one canonical set of signed transport headers to `record`.
    ///
    /// The signature binds topic, tenant, binary Kafka key, payload digest,
    /// producer, key ID, event ID, issuance, and expiry. `event_id` should be
    /// the immutable domain event ID already persisted in the producer outbox.
    /// Caller-supplied reserved attestation headers are rejected.
    pub fn attest(
        &self,
        record: DurableEventRecord,
        event_id: &str,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) -> Result<DurableEventRecord, AttestationConfigurationError> {
        if !valid_identifier(event_id, MAX_EVENT_ID_BYTES) {
            return Err(AttestationConfigurationError::InvalidEventId);
        }
        if issued_at_ms < 0 || expires_at_ms <= issued_at_ms {
            return Err(AttestationConfigurationError::InvalidAttestationTime);
        }
        if record
            .headers()
            .iter()
            .any(|header| is_reserved_header(header.name()))
        {
            return Err(AttestationConfigurationError::ReservedHeaderCollision);
        }

        let projection = signing_projection(
            record.topic(),
            record.tenant_id(),
            record.key(),
            record.payload(),
            &self.producer_service,
            &self.key_id,
            event_id,
            issued_at_ms,
            expires_at_ms,
        )
        .map_err(|()| AttestationConfigurationError::InvalidRecord)?;
        let signature = self.signing_key.sign(&projection);

        let mut headers = record.headers().to_vec();
        let reserved = [
            (HEADER_VERSION, ATTESTATION_VERSION.to_vec()),
            (
                HEADER_PRODUCER_SERVICE,
                self.producer_service.as_bytes().to_vec(),
            ),
            (HEADER_TENANT_ID, record.tenant_id().as_bytes().to_vec()),
            (HEADER_SIGNING_KEY_ID, self.key_id.as_bytes().to_vec()),
            (HEADER_EVENT_ID, event_id.as_bytes().to_vec()),
            (HEADER_ISSUED_AT_MS, issued_at_ms.to_string().into_bytes()),
            (HEADER_EXPIRES_AT_MS, expires_at_ms.to_string().into_bytes()),
            (
                HEADER_SIGNATURE,
                hex::encode(signature.to_bytes()).into_bytes(),
            ),
        ];
        for (name, value) in reserved {
            headers.push(
                DurableEventHeader::new(name, value)
                    .map_err(|_| AttestationConfigurationError::InvalidRecord)?,
            );
        }
        record
            .with_headers(headers)
            .map_err(|_| AttestationConfigurationError::InvalidRecord)
    }
}

/// Rotation-aware verifier containing only public Ed25519 keys.
///
/// Configure each authorized producer/key-ID pair through
/// [`Self::insert_verifying_key`]. Overlapping public keys allow bounded
/// rotation without giving consumers any producer private-key capability.
/// Raw Kafka records must be verified before payload parsing or state changes.
pub struct ProducerAttestationVerifier {
    max_validity_ms: i64,
    max_future_skew_ms: i64,
    verifying_keys: HashMap<String, HashMap<String, VerifyingKey>>,
}

impl fmt::Debug for ProducerAttestationVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_count: usize = self.verifying_keys.values().map(HashMap::len).sum();
        formatter
            .debug_struct("ProducerAttestationVerifier")
            .field("max_validity_ms", &self.max_validity_ms)
            .field("max_future_skew_ms", &self.max_future_skew_ms)
            .field("producer_count", &self.verifying_keys.len())
            .field("verifying_key_count", &key_count)
            .finish_non_exhaustive()
    }
}

impl ProducerAttestationVerifier {
    /// Creates an empty verifier with validity and future-clock-skew policies
    /// expressed in milliseconds.
    pub fn new(
        max_validity_ms: i64,
        max_future_skew_ms: i64,
    ) -> Result<Self, AttestationConfigurationError> {
        if max_validity_ms <= 0 || max_future_skew_ms < 0 {
            return Err(AttestationConfigurationError::InvalidVerificationWindow);
        }
        Ok(Self {
            max_validity_ms,
            max_future_skew_ms,
            verifying_keys: HashMap::new(),
        })
    }

    /// Adds one producer public key without replacing an existing key ID.
    ///
    /// Insert both old and new key IDs during a rotation overlap. Reusing an
    /// existing producer/key-ID pair is rejected to prevent silent public-key
    /// substitution.
    pub fn insert_verifying_key(
        &mut self,
        producer_service: impl Into<String>,
        key_id: impl Into<String>,
        public_verifying_key: Vec<u8>,
    ) -> Result<(), AttestationConfigurationError> {
        let producer_service = producer_service.into();
        let key_id = key_id.into();
        if !valid_identifier(&producer_service, MAX_PRODUCER_SERVICE_BYTES) {
            return Err(AttestationConfigurationError::InvalidProducerService);
        }
        if !valid_identifier(&key_id, MAX_KEY_ID_BYTES) {
            return Err(AttestationConfigurationError::InvalidKeyId);
        }
        if public_verifying_key.len() != ED25519_PUBLIC_KEY_BYTES {
            return Err(
                AttestationConfigurationError::InvalidPublicVerifyingKeyLength {
                    expected: ED25519_PUBLIC_KEY_BYTES,
                    actual: public_verifying_key.len(),
                },
            );
        }
        let bytes: [u8; ED25519_PUBLIC_KEY_BYTES] = public_verifying_key
            .as_slice()
            .try_into()
            .map_err(|_| AttestationConfigurationError::InvalidPublicVerifyingKey)?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| AttestationConfigurationError::InvalidPublicVerifyingKey)?;

        match self
            .verifying_keys
            .entry(producer_service)
            .or_default()
            .entry(key_id)
        {
            Entry::Vacant(entry) => {
                entry.insert(verifying_key);
                Ok(())
            }
            Entry::Occupied(_) => Err(AttestationConfigurationError::DuplicateVerifyingKey),
        }
    }

    /// Authenticates a raw durable Kafka record before payload parsing.
    ///
    /// Pass the broker-provided topic, binary key, raw payload, and complete
    /// header iterator unchanged. The tenant is bootstrapped exclusively from
    /// its canonical signed header; callers cannot supply or infer it from the
    /// payload. After success, trust only the returned producer, event, and
    /// tenant identity and compare any payload metadata against it.
    ///
    /// A malformed or mismatched signature returns an authentication error.
    /// `IssuedInFuture`, `Expired`, `ValidityTooLong`, and `InvalidTimeRange`
    /// are emitted only after the signature has authenticated the timestamps.
    /// Successful verification does not prevent replay: persist and dedupe
    /// the returned event ID in a verified-tenant-scoped inbox before
    /// committing the source offset.
    #[allow(clippy::too_many_arguments)]
    pub fn verify<'a, I>(
        &self,
        topic: &str,
        key: &[u8],
        payload: &[u8],
        headers: I,
        now_ms: i64,
    ) -> Result<VerifiedProducerAttestation, AttestationVerificationError>
    where
        I: IntoIterator<Item = (&'a str, Option<&'a [u8]>)>,
    {
        validate_transport_input(topic, key, payload, now_ms)?;
        let headers = collect_reserved_headers(headers)?;

        let version = required_header(&headers, HEADER_VERSION)?;
        if version != ATTESTATION_VERSION {
            return Err(AttestationVerificationError::UnsupportedVersion);
        }
        let producer_service = parse_identifier(
            required_header(&headers, HEADER_PRODUCER_SERVICE)?,
            MAX_PRODUCER_SERVICE_BYTES,
        )?;
        let tenant_id = parse_tenant_id(required_header(&headers, HEADER_TENANT_ID)?)?;
        let key_id = parse_identifier(
            required_header(&headers, HEADER_SIGNING_KEY_ID)?,
            MAX_KEY_ID_BYTES,
        )?;
        let event_id = parse_identifier(
            required_header(&headers, HEADER_EVENT_ID)?,
            MAX_EVENT_ID_BYTES,
        )?;
        let issued_at_ms = parse_timestamp(required_header(&headers, HEADER_ISSUED_AT_MS)?)?;
        let expires_at_ms = parse_timestamp(required_header(&headers, HEADER_EXPIRES_AT_MS)?)?;
        let signature = parse_signature(required_header(&headers, HEADER_SIGNATURE)?)?;

        let producer_keys = self
            .verifying_keys
            .get(producer_service)
            .ok_or(AttestationVerificationError::UnknownProducer)?;
        let verifying_key = producer_keys
            .get(key_id)
            .ok_or(AttestationVerificationError::UnknownKey)?;

        let projection = signing_projection(
            topic,
            tenant_id,
            key,
            payload,
            producer_service,
            key_id,
            event_id,
            issued_at_ms,
            expires_at_ms,
        )
        .map_err(|()| AttestationVerificationError::InvalidTransportInput)?;
        verifying_key
            .verify_strict(&projection, &signature)
            .map_err(|_| AttestationVerificationError::SignatureMismatch)?;

        // Clock-policy classifications are meaningful only after the record
        // has been authenticated. Otherwise an attacker could turn a forged
        // signature into an apparently retryable clock failure by changing a
        // timestamp header.
        if expires_at_ms <= issued_at_ms {
            return Err(AttestationVerificationError::InvalidTimeRange);
        }
        if issued_at_ms > now_ms.saturating_add(self.max_future_skew_ms) {
            return Err(AttestationVerificationError::IssuedInFuture);
        }
        if expires_at_ms <= now_ms {
            return Err(AttestationVerificationError::Expired);
        }
        if expires_at_ms - issued_at_ms > self.max_validity_ms {
            return Err(AttestationVerificationError::ValidityTooLong);
        }

        Ok(VerifiedProducerAttestation {
            producer_service: producer_service.to_owned(),
            key_id: key_id.to_owned(),
            event_id: event_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            issued_at_ms,
            expires_at_ms,
        })
    }
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= max_bytes
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

fn parse_identifier(value: &[u8], max_bytes: usize) -> Result<&str, AttestationVerificationError> {
    let value =
        std::str::from_utf8(value).map_err(|_| AttestationVerificationError::InvalidHeader)?;
    if !valid_identifier(value, max_bytes) {
        return Err(AttestationVerificationError::InvalidHeader);
    }
    Ok(value)
}

fn parse_tenant_id(value: &[u8]) -> Result<&str, AttestationVerificationError> {
    let tenant_id =
        std::str::from_utf8(value).map_err(|_| AttestationVerificationError::InvalidHeader)?;
    if tenant_id.is_empty()
        || tenant_id.len() > super::MAX_DURABLE_TENANT_ID_BYTES
        || tenant_id.trim() != tenant_id
        || tenant_id.chars().any(char::is_control)
    {
        return Err(AttestationVerificationError::InvalidHeader);
    }
    Ok(tenant_id)
}

fn parse_timestamp(value: &[u8]) -> Result<i64, AttestationVerificationError> {
    if value.is_empty()
        || value.len() > 19
        || !value.iter().all(u8::is_ascii_digit)
        || (value.len() > 1 && value[0] == b'0')
    {
        return Err(AttestationVerificationError::InvalidHeader);
    }
    std::str::from_utf8(value)
        .map_err(|_| AttestationVerificationError::InvalidHeader)?
        .parse::<i64>()
        .map_err(|_| AttestationVerificationError::InvalidHeader)
}

fn parse_signature(value: &[u8]) -> Result<Signature, AttestationVerificationError> {
    if value.len() != ED25519_SIGNATURE_HEX_BYTES
        || !value
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AttestationVerificationError::MalformedSignature);
    }
    let mut signature = [0_u8; ED25519_SIGNATURE_BYTES];
    hex::decode_to_slice(value, &mut signature)
        .map_err(|_| AttestationVerificationError::MalformedSignature)?;
    Ok(Signature::from_bytes(&signature))
}

fn collect_reserved_headers<'a, I>(
    headers: I,
) -> Result<HashMap<&'a str, &'a [u8]>, AttestationVerificationError>
where
    I: IntoIterator<Item = (&'a str, Option<&'a [u8]>)>,
{
    let mut reserved = HashMap::with_capacity(RESERVED_HEADERS.len());
    let mut header_count = 0_usize;
    for (name, value) in headers {
        header_count = header_count.saturating_add(1);
        if header_count > super::MAX_DURABLE_HEADERS {
            return Err(AttestationVerificationError::InvalidHeader);
        }
        match RESERVED_HEADERS
            .iter()
            .find(|reserved_name| name.eq_ignore_ascii_case(reserved_name))
        {
            Some(reserved_name) if name != *reserved_name => {
                return Err(AttestationVerificationError::InvalidHeader);
            }
            Some(_) => {}
            None => continue,
        }
        let value = value.ok_or(AttestationVerificationError::InvalidHeader)?;
        if reserved.insert(name, value).is_some() {
            return Err(AttestationVerificationError::DuplicateHeader);
        }
    }
    Ok(reserved)
}

fn required_header<'a>(
    headers: &HashMap<&str, &'a [u8]>,
    name: &str,
) -> Result<&'a [u8], AttestationVerificationError> {
    headers
        .get(name)
        .copied()
        .ok_or(AttestationVerificationError::MissingHeader)
}

fn is_reserved_header(name: &str) -> bool {
    RESERVED_HEADERS.contains(&name)
}

fn validate_transport_input(
    topic: &str,
    key: &[u8],
    payload: &[u8],
    now_ms: i64,
) -> Result<(), AttestationVerificationError> {
    let valid_topic = !topic.is_empty()
        && !matches!(topic, "." | "..")
        && topic.len() <= 249
        && topic
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !valid_topic
        || key.is_empty()
        || key.len() > super::MAX_DURABLE_KEY_BYTES
        || payload.is_empty()
        || payload.len() > super::MAX_DURABLE_PAYLOAD_BYTES
        || now_ms < 0
    {
        return Err(AttestationVerificationError::InvalidTransportInput);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn signing_projection(
    topic: &str,
    tenant_id: &str,
    key: &[u8],
    payload: &[u8],
    producer_service: &str,
    key_id: &str,
    event_id: &str,
    issued_at_ms: i64,
    expires_at_ms: i64,
) -> Result<Vec<u8>, ()> {
    let payload_digest = Sha256::digest(payload);
    let issued_at = issued_at_ms.to_be_bytes();
    let expires_at = expires_at_ms.to_be_bytes();
    let fields: [&[u8]; 9] = [
        topic.as_bytes(),
        tenant_id.as_bytes(),
        key,
        payload_digest.as_slice(),
        producer_service.as_bytes(),
        key_id.as_bytes(),
        event_id.as_bytes(),
        &issued_at,
        &expires_at,
    ];
    let framed_bytes = fields
        .iter()
        .try_fold(DOMAIN_SEPARATOR.len(), |total, field| {
            u64::try_from(field.len()).map_err(|_| ())?;
            total
                .checked_add(8)
                .and_then(|value| value.checked_add(field.len()))
                .ok_or(())
        })?;
    let mut projection = Vec::with_capacity(framed_bytes);
    projection.extend_from_slice(DOMAIN_SEPARATOR);
    for field in fields {
        let length = u64::try_from(field.len()).map_err(|_| ())?;
        projection.extend_from_slice(&length.to_be_bytes());
        projection.extend_from_slice(field);
    }
    Ok(projection)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use ed25519_dalek::{SigningKey, VerifyingKey};
    use sha2::Digest as _;

    use super::*;
    use crate::{DurableEventHeader, DurableEventRecord};

    const NOW_MS: i64 = 1_750_000_000_000;
    const ISSUED_AT_MS: i64 = NOW_MS - 1_000;
    const EXPIRES_AT_MS: i64 = NOW_MS + 60_000;
    const PRODUCER: &str = "runtime-service";
    const KEY_ID: &str = "runtime-2026-07-a";
    const EVENT_ID: &str = "evt-01HZ.TEST:1";

    fn seed(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    fn public_key(byte: u8) -> Vec<u8> {
        SigningKey::from_bytes(&[byte; 32])
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    fn record() -> DurableEventRecord {
        DurableEventRecord::new(
            "astro.execution.external-job.v1",
            "tenant-a",
            b"tenant-a\0job-1".to_vec(),
            br#"{"event":"requested"}"#.to_vec(),
        )
        .expect("fixture record is valid")
        .with_headers(vec![
            DurableEventHeader::new("traceparent", b"00-safe-trace".to_vec())
                .expect("fixture header is valid"),
        ])
        .expect("fixture headers are valid")
    }

    fn signer() -> ProducerAttestationSigner {
        ProducerAttestationSigner::new(PRODUCER, KEY_ID, seed(7)).expect("fixture signer is valid")
    }

    fn verifier() -> ProducerAttestationVerifier {
        let mut verifier = ProducerAttestationVerifier::new(120_000, 5_000)
            .expect("fixture verifier policy is valid");
        verifier
            .insert_verifying_key(PRODUCER, KEY_ID, public_key(7))
            .expect("fixture public key is valid");
        verifier
    }

    fn attest() -> DurableEventRecord {
        signer()
            .attest(record(), EVENT_ID, ISSUED_AT_MS, EXPIRES_AT_MS)
            .expect("fixture attestation succeeds")
    }

    fn headers(record: &DurableEventRecord) -> Vec<(&str, Option<&[u8]>)> {
        record
            .headers()
            .iter()
            .map(|header| (header.name(), Some(header.value())))
            .collect()
    }

    fn verify(
        verifier: &ProducerAttestationVerifier,
        record: &DurableEventRecord,
        now_ms: i64,
    ) -> Result<VerifiedProducerAttestation, AttestationVerificationError> {
        verifier.verify(
            record.topic(),
            record.key(),
            record.payload(),
            headers(record),
            now_ms,
        )
    }

    fn replace_header(
        record: &DurableEventRecord,
        name: &str,
        value: Vec<u8>,
    ) -> Vec<(String, Option<Vec<u8>>)> {
        record
            .headers()
            .iter()
            .map(|header| {
                (
                    header.name().to_owned(),
                    Some(if header.name() == name {
                        value.clone()
                    } else {
                        header.value().to_vec()
                    }),
                )
            })
            .collect()
    }

    fn owned_headers(headers: &[(String, Option<Vec<u8>>)]) -> Vec<(&str, Option<&[u8]>)> {
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_deref()))
            .collect()
    }

    fn signature_hex(record: &DurableEventRecord) -> &str {
        let bytes = record
            .headers()
            .iter()
            .find(|header| header.name() == "x-warpin-signature-ed25519")
            .expect("signature header exists")
            .value();
        std::str::from_utf8(bytes).expect("signature is ASCII")
    }

    #[test]
    fn valid_attestation_preserves_caller_headers_and_returns_identity() {
        let signed = attest();
        let verified = verify(&verifier(), &signed, NOW_MS).expect("attestation verifies");

        assert_eq!(verified.producer_service, PRODUCER);
        assert_eq!(verified.key_id, KEY_ID);
        assert_eq!(verified.event_id, EVENT_ID);
        assert_eq!(verified.tenant_id, "tenant-a");
        assert_eq!(verified.issued_at_ms, ISSUED_AT_MS);
        assert_eq!(verified.expires_at_ms, EXPIRES_AT_MS);
        assert_eq!(signed.headers()[0].name(), "traceparent");
        assert_eq!(signed.headers().len(), 9);
    }

    #[test]
    fn signer_uses_the_frozen_length_framed_projection() {
        let signed = attest();
        let signature = hex::decode(signature_hex(&signed)).expect("signature is hexadecimal");
        let signature: [u8; 64] = signature.try_into().expect("signature has fixed length");

        let mut projection = b"warpin.durable-event-attestation.v1".to_vec();
        let payload_digest = sha2::Sha256::digest(signed.payload());
        for field in [
            signed.topic().as_bytes(),
            signed.tenant_id().as_bytes(),
            signed.key(),
            payload_digest.as_slice(),
            PRODUCER.as_bytes(),
            KEY_ID.as_bytes(),
            EVENT_ID.as_bytes(),
            &ISSUED_AT_MS.to_be_bytes(),
            &EXPIRES_AT_MS.to_be_bytes(),
        ] {
            projection.extend_from_slice(&(field.len() as u64).to_be_bytes());
            projection.extend_from_slice(field);
        }

        VerifyingKey::from_bytes(&public_key(7).try_into().expect("public key length"))
            .expect("public key parses")
            .verify_strict(
                &projection,
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .expect("signature covers the exact frozen projection");
    }

    #[test]
    fn verifier_accepts_overlapping_rotation_keys() {
        let old = signer()
            .attest(record(), "old-event", ISSUED_AT_MS, EXPIRES_AT_MS)
            .unwrap();
        let new_signer =
            ProducerAttestationSigner::new(PRODUCER, "runtime-2026-07-b", seed(8)).unwrap();
        let new = new_signer
            .attest(record(), "new-event", ISSUED_AT_MS, EXPIRES_AT_MS)
            .unwrap();
        let mut verifier = verifier();
        verifier
            .insert_verifying_key(PRODUCER, "runtime-2026-07-b", public_key(8))
            .unwrap();

        assert_eq!(
            verify(&verifier, &old, NOW_MS).unwrap().event_id,
            "old-event"
        );
        assert_eq!(
            verify(&verifier, &new, NOW_MS).unwrap().event_id,
            "new-event"
        );
    }

    #[test]
    fn debug_output_redacts_all_private_key_material() {
        let private = seed(171);
        let private_hex = hex::encode(&private);
        let debug = format!(
            "{:?}",
            ProducerAttestationSigner::new(PRODUCER, KEY_ID, private).unwrap()
        );

        assert!(!debug.contains(&private_hex));
        assert!(!debug.contains("171"));
        assert!(debug.contains("private_key"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn another_producers_public_key_cannot_authenticate_the_record() {
        let signed = attest();
        let mut wrong = ProducerAttestationVerifier::new(120_000, 5_000).unwrap();
        wrong
            .insert_verifying_key("processing-service", KEY_ID, public_key(8))
            .unwrap();
        assert!(matches!(
            verify(&wrong, &signed, NOW_MS),
            Err(AttestationVerificationError::UnknownProducer)
        ));

        let changed = replace_header(
            &signed,
            "x-warpin-producer-service",
            b"processing-service".to_vec(),
        );
        assert!(matches!(
            wrong.verify(
                signed.topic(),
                signed.key(),
                signed.payload(),
                owned_headers(&changed),
                NOW_MS
            ),
            Err(AttestationVerificationError::SignatureMismatch)
        ));
    }

    #[test]
    fn configuration_rejects_invalid_identifiers_keys_and_windows() {
        assert!(matches!(
            ProducerAttestationSigner::new(" bad", KEY_ID, seed(1)),
            Err(AttestationConfigurationError::InvalidProducerService)
        ));
        assert!(matches!(
            ProducerAttestationSigner::new(PRODUCER, "bad/key", seed(1)),
            Err(AttestationConfigurationError::InvalidKeyId)
        ));
        assert!(matches!(
            ProducerAttestationSigner::new(PRODUCER, KEY_ID, vec![1; 31]),
            Err(AttestationConfigurationError::InvalidPrivateSigningKeyLength { .. })
        ));
        assert!(matches!(
            ProducerAttestationVerifier::new(0, 0),
            Err(AttestationConfigurationError::InvalidVerificationWindow)
        ));
        assert!(matches!(
            ProducerAttestationVerifier::new(1, -1),
            Err(AttestationConfigurationError::InvalidVerificationWindow)
        ));
        let mut verifier = verifier();
        assert!(matches!(
            verifier.insert_verifying_key(PRODUCER, "new", vec![1; 31]),
            Err(AttestationConfigurationError::InvalidPublicVerifyingKeyLength { .. })
        ));
        assert!(matches!(
            verifier.insert_verifying_key(PRODUCER, KEY_ID, public_key(8)),
            Err(AttestationConfigurationError::DuplicateVerifyingKey)
        ));
    }

    #[test]
    fn signer_rejects_invalid_event_time_and_reserved_header_collision() {
        assert!(matches!(
            signer().attest(record(), "bad/event", ISSUED_AT_MS, EXPIRES_AT_MS),
            Err(AttestationConfigurationError::InvalidEventId)
        ));
        assert!(matches!(
            signer().attest(record(), EVENT_ID, -1, EXPIRES_AT_MS),
            Err(AttestationConfigurationError::InvalidAttestationTime)
        ));
        assert!(matches!(
            signer().attest(record(), EVENT_ID, EXPIRES_AT_MS, ISSUED_AT_MS),
            Err(AttestationConfigurationError::InvalidAttestationTime)
        ));
        let colliding = record()
            .with_headers(vec![
                DurableEventHeader::new("x-warpin-event-id", b"caller".to_vec()).unwrap(),
            ])
            .unwrap();
        assert!(matches!(
            signer().attest(colliding, EVENT_ID, ISSUED_AT_MS, EXPIRES_AT_MS),
            Err(AttestationConfigurationError::ReservedHeaderCollision)
        ));
    }

    #[test]
    fn verifier_rejects_every_missing_and_duplicate_reserved_header() {
        let signed = attest();
        let reserved: Vec<_> = signed
            .headers()
            .iter()
            .filter(|header| header.name().starts_with("x-warpin-"))
            .collect();
        for missing in &reserved {
            let remaining: Vec<_> = signed
                .headers()
                .iter()
                .filter(|header| header.name() != missing.name())
                .map(|header| (header.name(), Some(header.value())))
                .collect();
            assert!(matches!(
                verifier().verify(
                    signed.topic(),
                    signed.key(),
                    signed.payload(),
                    remaining,
                    NOW_MS
                ),
                Err(AttestationVerificationError::MissingHeader)
            ));

            let mut duplicate = headers(&signed);
            duplicate.push((missing.name(), Some(missing.value())));
            assert!(matches!(
                verifier().verify(
                    signed.topic(),
                    signed.key(),
                    signed.payload(),
                    duplicate,
                    NOW_MS
                ),
                Err(AttestationVerificationError::DuplicateHeader)
            ));
        }
    }

    #[test]
    fn verifier_rejects_every_noncanonical_case_variant_of_a_reserved_header() {
        let signed = attest();
        for reserved_name in RESERVED_HEADERS {
            let lookalike: String = reserved_name
                .chars()
                .enumerate()
                .map(|(index, character)| {
                    if character.is_ascii_alphabetic() && index % 2 == 0 {
                        character.to_ascii_uppercase()
                    } else {
                        character
                    }
                })
                .collect();
            assert_ne!(lookalike, reserved_name);
            assert!(lookalike.eq_ignore_ascii_case(reserved_name));

            let changed: Vec<_> = signed
                .headers()
                .iter()
                .map(|header| {
                    (
                        if header.name() == reserved_name {
                            lookalike.clone()
                        } else {
                            header.name().to_owned()
                        },
                        Some(header.value().to_vec()),
                    )
                })
                .collect();
            assert_eq!(
                verifier()
                    .verify(
                        signed.topic(),
                        signed.key(),
                        signed.payload(),
                        owned_headers(&changed),
                        NOW_MS,
                    )
                    .unwrap_err(),
                AttestationVerificationError::InvalidHeader,
                "reserved header lookalike {lookalike} must be rejected",
            );
        }
    }

    #[test]
    fn verifier_keeps_ordinary_non_reserved_headers_case_sensitive_and_ignored() {
        let signed = attest();
        let mut headers = headers(&signed);
        headers.push(("TraceParent", Some(b"ordinary-caller-header")));

        let verified = verifier()
            .verify(
                signed.topic(),
                signed.key(),
                signed.payload(),
                headers,
                NOW_MS,
            )
            .expect("ordinary non-reserved headers do not affect authentication");
        assert_eq!(verified.event_id, EVENT_ID);
    }

    #[test]
    fn verifier_rejects_invalid_header_values() {
        let signed = attest();
        let cases = [
            (
                "x-warpin-attestation-version",
                b"2".to_vec(),
                AttestationVerificationError::UnsupportedVersion,
            ),
            (
                "x-warpin-producer-service",
                vec![0xff],
                AttestationVerificationError::InvalidHeader,
            ),
            (
                "x-warpin-producer-service",
                vec![b'a'; 129],
                AttestationVerificationError::InvalidHeader,
            ),
            (
                "x-warpin-tenant-id",
                vec![0xff],
                AttestationVerificationError::InvalidHeader,
            ),
            (
                "x-warpin-tenant-id",
                b" tenant-a".to_vec(),
                AttestationVerificationError::InvalidHeader,
            ),
            (
                "x-warpin-tenant-id",
                b"tenant-a\n".to_vec(),
                AttestationVerificationError::InvalidHeader,
            ),
            (
                "x-warpin-tenant-id",
                vec![b'a'; 257],
                AttestationVerificationError::InvalidHeader,
            ),
            (
                "x-warpin-signing-key-id",
                b"bad/key".to_vec(),
                AttestationVerificationError::InvalidHeader,
            ),
            (
                "x-warpin-event-id",
                b"bad event".to_vec(),
                AttestationVerificationError::InvalidHeader,
            ),
            (
                "x-warpin-issued-at-ms",
                b"01".to_vec(),
                AttestationVerificationError::InvalidHeader,
            ),
            (
                "x-warpin-expires-at-ms",
                b"-1".to_vec(),
                AttestationVerificationError::InvalidHeader,
            ),
            (
                "x-warpin-signature-ed25519",
                b"AA".repeat(64),
                AttestationVerificationError::MalformedSignature,
            ),
            (
                "x-warpin-signature-ed25519",
                b"0".repeat(126),
                AttestationVerificationError::MalformedSignature,
            ),
        ];
        for (name, value, expected) in cases {
            let changed = replace_header(&signed, name, value);
            assert_eq!(
                verifier()
                    .verify(
                        signed.topic(),
                        signed.key(),
                        signed.payload(),
                        owned_headers(&changed),
                        NOW_MS
                    )
                    .unwrap_err(),
                expected,
                "header {name}"
            );
        }

        let mut missing_value: Vec<_> = signed
            .headers()
            .iter()
            .map(|header| (header.name(), Some(header.value())))
            .collect();
        let index = signed
            .headers()
            .iter()
            .position(|header| header.name() == "x-warpin-event-id")
            .unwrap();
        missing_value[index].1 = None;
        assert_eq!(
            verifier()
                .verify(
                    signed.topic(),
                    signed.key(),
                    signed.payload(),
                    missing_value,
                    NOW_MS
                )
                .unwrap_err(),
            AttestationVerificationError::InvalidHeader
        );
    }

    #[test]
    fn verifier_rejects_unknown_producer_and_key() {
        let signed = attest();
        let no_keys = ProducerAttestationVerifier::new(120_000, 5_000).unwrap();
        assert_eq!(
            verify(&no_keys, &signed, NOW_MS).unwrap_err(),
            AttestationVerificationError::UnknownProducer
        );

        let mut wrong_key = ProducerAttestationVerifier::new(120_000, 5_000).unwrap();
        wrong_key
            .insert_verifying_key(PRODUCER, "another-key", public_key(7))
            .unwrap();
        assert_eq!(
            verify(&wrong_key, &signed, NOW_MS).unwrap_err(),
            AttestationVerificationError::UnknownKey
        );
    }

    #[test]
    fn verifier_bootstraps_and_binds_header_tenant_topic_key_and_payload() {
        let signed = attest();
        let verifier = verifier();
        let changed_tenant = replace_header(&signed, "x-warpin-tenant-id", b"tenant-b".to_vec());
        for result in [
            verifier.verify(
                "another.topic",
                signed.key(),
                signed.payload(),
                headers(&signed),
                NOW_MS,
            ),
            verifier.verify(
                signed.topic(),
                signed.key(),
                signed.payload(),
                owned_headers(&changed_tenant),
                NOW_MS,
            ),
            verifier.verify(
                signed.topic(),
                b"tenant-a\0job-2",
                signed.payload(),
                headers(&signed),
                NOW_MS,
            ),
            verifier.verify(
                signed.topic(),
                signed.key(),
                br#"{"event":"cancelled"}"#,
                headers(&signed),
                NOW_MS,
            ),
        ] {
            assert_eq!(
                result.unwrap_err(),
                AttestationVerificationError::SignatureMismatch
            );
        }
    }

    #[test]
    fn verifier_enforces_clock_boundaries_and_maximum_validity() {
        let future = signer()
            .attest(record(), EVENT_ID, NOW_MS + 5_001, NOW_MS + 60_000)
            .unwrap();
        assert_eq!(
            verify(&verifier(), &future, NOW_MS).unwrap_err(),
            AttestationVerificationError::IssuedInFuture
        );

        let boundary = signer()
            .attest(record(), EVENT_ID, NOW_MS + 5_000, NOW_MS + 60_000)
            .unwrap();
        verify(&verifier(), &boundary, NOW_MS).expect("configured skew boundary is inclusive");

        let expired = signer()
            .attest(record(), EVENT_ID, NOW_MS - 60_000, NOW_MS)
            .unwrap();
        assert_eq!(
            verify(&verifier(), &expired, NOW_MS).unwrap_err(),
            AttestationVerificationError::Expired
        );

        let excessive = signer()
            .attest(record(), EVENT_ID, NOW_MS - 1, NOW_MS + 120_000)
            .unwrap();
        assert_eq!(
            verify(&verifier(), &excessive, NOW_MS).unwrap_err(),
            AttestationVerificationError::ValidityTooLong
        );
    }

    #[test]
    fn unauthenticated_timestamp_tampering_cannot_masquerade_as_clock_policy_failure() {
        let signed = attest();
        for (name, value) in [
            ("x-warpin-issued-at-ms", (NOW_MS + 5_001).to_string()),
            ("x-warpin-expires-at-ms", NOW_MS.to_string()),
        ] {
            let changed = replace_header(&signed, name, value.into_bytes());
            assert_eq!(
                verifier()
                    .verify(
                        signed.topic(),
                        signed.key(),
                        signed.payload(),
                        owned_headers(&changed),
                        NOW_MS,
                    )
                    .unwrap_err(),
                AttestationVerificationError::SignatureMismatch,
                "tampered header {name} must fail authentication first",
            );
        }
    }

    #[test]
    fn verifier_rejects_malformed_or_mismatched_signature() {
        let signed = attest();
        let changed = replace_header(&signed, "x-warpin-signature-ed25519", b"0".repeat(128));
        assert_eq!(
            verifier()
                .verify(
                    signed.topic(),
                    signed.key(),
                    signed.payload(),
                    owned_headers(&changed),
                    NOW_MS
                )
                .unwrap_err(),
            AttestationVerificationError::SignatureMismatch
        );
    }

    #[test]
    fn verifier_rejects_oversized_transport_inputs_before_hashing() {
        let signed = attest();
        let huge_payload = vec![0; 16 * 1024 * 1024 + 1];
        assert_eq!(
            verifier()
                .verify(
                    signed.topic(),
                    signed.key(),
                    &huge_payload,
                    headers(&signed),
                    NOW_MS
                )
                .unwrap_err(),
            AttestationVerificationError::InvalidTransportInput
        );
    }

    #[test]
    fn signature_is_lowercase_canonical_hex() {
        let signature = signature_hex(&attest()).to_owned();
        assert_eq!(signature.len(), 128);
        assert!(
            signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        );
        let mut rendered = String::new();
        for byte in hex::decode(&signature).unwrap() {
            write!(&mut rendered, "{byte:02x}").unwrap();
        }
        assert_eq!(rendered, signature);
    }
}
