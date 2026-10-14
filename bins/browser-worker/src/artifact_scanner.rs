//! Authenticated ClamAV observations. VERSION identifies reported metadata, not DB contents.
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use browserd_worker::{
    ArtifactScanVerdict, ArtifactScannerObservation, DependencyError, WorkerClock,
};
use chrono::NaiveDateTime;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const CHUNK_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 4096;
const MAX_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactScanResult {
    pub verdict: ArtifactScanVerdict,
    pub observation: Option<ArtifactScannerObservation>,
}

#[async_trait]
pub trait ArtifactScanner: Send + Sync + 'static {
    async fn scan(&self, bytes: &[u8]) -> Result<ArtifactScanVerdict, DependencyError>;

    /// Legacy adapters provide no evidence. Production publication must reject that absence.
    /// A nonclean observation attests a complete authenticated scan of the exact bytes, not safety.
    async fn scan_with_observation(
        &self,
        bytes: &[u8],
    ) -> Result<ArtifactScanResult, DependencyError> {
        Ok(ArtifactScanResult {
            verdict: self.scan(bytes).await?,
            observation: None,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ClamAvFreshnessPolicy {
    max_database_age_millis: u64,
    max_future_skew_millis: u64,
}
impl ClamAvFreshnessPolicy {
    /// The caller explicitly asserts that clamd formats VERSION dates in UTC (TZ=UTC).
    /// Native VERSION dates have no offset, so the socket cannot verify this deployment contract.
    pub fn new_utc(max_age: Duration, future_skew: Duration) -> Result<Self, DependencyError> {
        if max_age.is_zero()
            || max_age > Duration::from_secs(7 * 24 * 60 * 60)
            || future_skew > MAX_TIMEOUT
        {
            return Err(DependencyError::Rejected);
        }
        let max_database_age_millis =
            u64::try_from(max_age.as_millis()).map_err(|_| DependencyError::Rejected)?;
        let max_future_skew_millis =
            u64::try_from(future_skew.as_millis()).map_err(|_| DependencyError::Rejected)?;
        if max_database_age_millis == 0 {
            return Err(DependencyError::Rejected);
        }
        Ok(Self {
            max_database_age_millis,
            max_future_skew_millis,
        })
    }
}

/// One UID-authenticated connection with equal VERSION observations bracketing INSTREAM.
/// This does not attest a digest of loaded signatures or protect against a trusted daemon's lies.
/// Protocol: <https://docs.clamav.net/manual/Usage/ClamdProtocol.html>.
pub struct UnixClamAvScanner {
    socket: PathBuf,
    expected_uid: u32,
    max_bytes: u64,
    timeout: Duration,
    policy: ClamAvFreshnessPolicy,
    clock: Arc<dyn WorkerClock>,
}
impl UnixClamAvScanner {
    pub fn new(
        socket: PathBuf,
        expected_uid: u32,
        max_bytes: u64,
        timeout: Duration,
        policy: ClamAvFreshnessPolicy,
        clock: Arc<dyn WorkerClock>,
    ) -> Result<Self, DependencyError> {
        if !socket.is_absolute() || max_bytes == 0 || timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(DependencyError::Rejected);
        }
        Ok(Self {
            socket,
            expected_uid,
            max_bytes,
            timeout,
            policy,
            clock,
        })
    }

    fn now(&self) -> Result<u64, DependencyError> {
        self.clock
            .now()
            .map(|now| now.get())
            .map_err(|_| DependencyError::Unavailable)
    }
}

#[derive(Eq, PartialEq)]
struct Version {
    program: String,
    database: u64,
    built_at: u64,
    digest: [u8; 32],
}
impl Version {
    fn parse(bytes: &[u8]) -> Result<Self, DependencyError> {
        let value = std::str::from_utf8(bytes).map_err(|_| DependencyError::Rejected)?;
        let mut parts = value
            .strip_prefix("ClamAV ")
            .ok_or(DependencyError::Rejected)?
            .split('/');
        let program = parts.next().ok_or(DependencyError::Rejected)?;
        let database = parts.next().ok_or(DependencyError::Rejected)?;
        let date = parts.next().ok_or(DependencyError::Rejected)?;
        if parts.next().is_some()
            || program.is_empty()
            || program.len() > 64
            || !program.bytes().all(|b| b.is_ascii_graphic())
            || database.is_empty()
            || !database.bytes().all(|b| b.is_ascii_digit())
            || database.starts_with('0')
        {
            return Err(DependencyError::Rejected);
        }
        let parsed = NaiveDateTime::parse_from_str(date, "%a %b %e %T %Y")
            .map_err(|_| DependencyError::Rejected)?;
        if parsed.format("%a %b %e %T %Y").to_string() != date {
            return Err(DependencyError::Rejected);
        }
        Ok(Self {
            program: program.to_owned(),
            database: database.parse().map_err(|_| DependencyError::Rejected)?,
            built_at: u64::try_from(parsed.and_utc().timestamp_millis())
                .map_err(|_| DependencyError::Rejected)?,
            digest: Sha256::digest(bytes).into(),
        })
    }

    fn fresh(&self, policy: ClamAvFreshnessPolicy, now: u64) -> Result<(), DependencyError> {
        if self.built_at > now.saturating_add(policy.max_future_skew_millis)
            || now.saturating_sub(self.built_at) > policy.max_database_age_millis
        {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }
}

async fn reply<R: AsyncRead + Unpin>(reader: &mut R, id: u8) -> Result<Vec<u8>, DependencyError> {
    let mut bytes = Vec::with_capacity(128);
    loop {
        let byte = reader
            .read_u8()
            .await
            .map_err(|_| DependencyError::Unavailable)?;
        if byte == 0 {
            break;
        }
        if bytes.len() == MAX_RESPONSE_BYTES {
            return Err(DependencyError::Rejected);
        }
        bytes.push(byte);
    }
    let prefix = [b'0' + id, b':', b' '];
    let payload = bytes
        .strip_prefix(&prefix)
        .ok_or(DependencyError::Rejected)?;
    Ok(payload.to_vec())
}

async fn send_stream<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    sent: &AtomicBool,
) -> Result<(), DependencyError> {
    writer
        .write_all(b"zINSTREAM\0")
        .await
        .map_err(|_| DependencyError::Unavailable)?;
    for chunk in bytes.chunks(CHUNK_BYTES) {
        let length = u32::try_from(chunk.len()).map_err(|_| DependencyError::Rejected)?;
        writer
            .write_all(&length.to_be_bytes())
            .await
            .map_err(|_| DependencyError::Unavailable)?;
        writer
            .write_all(chunk)
            .await
            .map_err(|_| DependencyError::Unavailable)?;
    }
    writer
        .write_all(&0_u32.to_be_bytes())
        .await
        .map_err(|_| DependencyError::Unavailable)?;
    sent.store(true, Ordering::Release);
    Ok(())
}

#[async_trait]
impl ArtifactScanner for UnixClamAvScanner {
    async fn scan(&self, bytes: &[u8]) -> Result<ArtifactScanVerdict, DependencyError> {
        self.scan_with_observation(bytes)
            .await
            .map(|result| result.verdict)
    }

    async fn scan_with_observation(
        &self,
        bytes: &[u8],
    ) -> Result<ArtifactScanResult, DependencyError> {
        let size = u64::try_from(bytes.len()).map_err(|_| DependencyError::Rejected)?;
        if size > self.max_bytes {
            return Err(DependencyError::Rejected);
        }
        tokio::time::timeout(self.timeout, async {
            let before = self.now()?;
            let stream = tokio::net::UnixStream::connect(&self.socket)
                .await
                .map_err(|_| DependencyError::Unavailable)?;
            let uid = stream
                .peer_cred()
                .map_err(|_| DependencyError::Unavailable)?
                .uid();
            if uid != self.expected_uid {
                return Err(DependencyError::Rejected);
            }
            let (mut reader, mut writer) = stream.into_split();
            writer
                .write_all(b"zIDSESSION\0zVERSION\0")
                .await
                .map_err(|_| DependencyError::Unavailable)?;
            let version = Version::parse(&reply(&mut reader, 1).await?)?;
            version.fresh(self.policy, before)?;
            let sent = AtomicBool::new(false);
            let response = {
                let sending = send_stream(&mut writer, bytes, &sent);
                let receiving = reply(&mut reader, 2);
                tokio::pin!(sending, receiving);
                tokio::select! {
                    response = &mut receiving => {
                        let response = response?;
                        if !sent.load(Ordering::Acquire) {
                            return rejected_reply(&response);
                        }
                        sending.await?;
                        response
                    }
                    sent = &mut sending => {
                        sent?;
                        receiving.await?
                    }
                }
            };
            let verdict = if response == b"stream: OK" {
                ArtifactScanVerdict::Clean
            } else {
                rejected_reply(&response)?.verdict
            };
            writer
                .write_all(b"zVERSION\0")
                .await
                .map_err(|_| DependencyError::Unavailable)?;
            let after_version = Version::parse(&reply(&mut reader, 3).await?)?;
            if after_version != version {
                return Err(DependencyError::Rejected);
            }
            writer
                .write_all(b"zEND\0")
                .await
                .map_err(|_| DependencyError::Unavailable)?;
            let mut trailing = [0];
            if reader
                .read(&mut trailing)
                .await
                .map_err(|_| DependencyError::Unavailable)?
                != 0
            {
                return Err(DependencyError::Rejected);
            }
            let after = self.now()?;
            version.fresh(self.policy, after)?;
            let observation = ArtifactScannerObservation {
                schema_version: 1,
                program_version: version.program,
                database_version: version.database,
                database_built_at_unix_millis: version.built_at,
                observed_before_unix_millis: before,
                observed_after_unix_millis: after,
                expected_peer_uid: self.expected_uid,
                peer_uid: uid,
                version_metadata_sha256: version.digest,
                scanned_size_bytes: size,
                scanned_checksum_sha256: Sha256::digest(bytes).into(),
                max_database_age_millis: self.policy.max_database_age_millis,
                max_future_skew_millis: self.policy.max_future_skew_millis,
            };
            observation
                .validate_at(after)
                .map_err(|_| DependencyError::Rejected)?;
            Ok(ArtifactScanResult {
                verdict,
                observation: Some(observation),
            })
        })
        .await
        .map_err(|_| DependencyError::Unavailable)?
    }
}

fn rejected_reply(response: &[u8]) -> Result<ArtifactScanResult, DependencyError> {
    let signature = response
        .strip_prefix(b"stream: ")
        .and_then(|name| name.strip_suffix(b" FOUND"));
    if signature.is_some_and(|name| {
        !name.is_empty()
            && name.first() != Some(&b' ')
            && name.last() != Some(&b' ')
            && name.iter().all(|b| b.is_ascii_graphic() || *b == b' ')
    }) {
        Ok(ArtifactScanResult {
            verdict: ArtifactScanVerdict::Rejected,
            observation: None,
        })
    } else {
        Err(DependencyError::Rejected)
    }
}
