use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{
    LeaseId, WorkerRetainedArtifactScope, WorkerRpcFailure, WorkerRpcFailureCode,
    WorkerSessionFence,
};
use crate::ArtifactPublication;
use crate::ArtifactReadStream;

#[derive(Clone, Debug, Eq, PartialEq)]
enum StreamScope {
    Live(WorkerSessionFence),
    Retained {
        scope: WorkerRetainedArtifactScope,
        publication: Box<ArtifactPublication>,
    },
}
struct Stream {
    scope: StreamScope,
    reader: Box<dyn ArtifactReadStream>,
    next_sequence: u64,
    expires: Instant,
}

pub(super) struct ArtifactStreams {
    streams: Mutex<HashMap<LeaseId, Stream>>,
    capacity: usize,
    ttl: Duration,
}

fn failure() -> WorkerRpcFailure {
    WorkerRpcFailure::new(
        WorkerRpcFailureCode::Dependency,
        "artifact stream unavailable",
    )
}

impl ArtifactStreams {
    pub(super) fn prune(&self) -> Result<(), WorkerRpcFailure> {
        self.streams
            .lock()
            .map_err(|_| failure())?
            .retain(|_, stream| stream.expires > Instant::now());
        Ok(())
    }
    pub(super) fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
            capacity,
            ttl,
        }
    }

    pub(super) fn open(
        &self,
        fence: WorkerSessionFence,
        reader: Box<dyn ArtifactReadStream>,
    ) -> Result<LeaseId, WorkerRpcFailure> {
        let mut streams = self.streams.lock().map_err(|_| failure())?;
        let now = Instant::now();
        streams.retain(|_, stream| stream.expires > now);
        if streams.len() >= self.capacity {
            return Err(failure());
        }
        let id = LeaseId::new();
        streams.insert(
            id.clone(),
            Stream {
                scope: StreamScope::Live(fence),
                reader,
                next_sequence: 0,
                expires: now + self.ttl,
            },
        );
        Ok(id)
    }

    pub(super) fn open_retained(
        &self,
        scope: WorkerRetainedArtifactScope,
        publication: ArtifactPublication,
        reader: Box<dyn ArtifactReadStream>,
        now_unix_millis: u64,
    ) -> Result<LeaseId, WorkerRpcFailure> {
        publication.validate().map_err(|_| failure())?;
        if scope.worker_id != *publication.original_fence().worker_id()
            || scope.worker_epoch == 0
            || scope.tenant_id != *publication.key().tenant_id()
            || scope.session_id != *publication.key().session_id()
            || now_unix_millis < publication.published_at_unix_millis()
            || now_unix_millis >= publication.expires_at_unix_millis()
        {
            return Err(failure());
        }
        let mut streams = self.streams.lock().map_err(|_| failure())?;
        let now = Instant::now();
        streams.retain(|_, stream| stream.expires > now);
        if streams.len() >= self.capacity {
            return Err(failure());
        }
        let ttl = self.ttl.min(Duration::from_millis(
            publication.expires_at_unix_millis() - now_unix_millis,
        ));
        let id = LeaseId::new();
        streams.insert(
            id.clone(),
            Stream {
                scope: StreamScope::Retained {
                    scope,
                    publication: Box::new(publication),
                },
                reader,
                next_sequence: 0,
                expires: now + ttl,
            },
        );
        Ok(id)
    }
    pub(super) fn read(
        &self,
        fence: &WorkerSessionFence,
        id: &LeaseId,
        sequence: u64,
    ) -> Result<Option<Vec<u8>>, WorkerRpcFailure> {
        self.read_scoped(&StreamScope::Live(fence.clone()), id, sequence, None)
    }
    pub(super) fn read_retained(
        &self,
        scope: &WorkerRetainedArtifactScope,
        id: &LeaseId,
        sequence: u64,
        now_unix_millis: u64,
    ) -> Result<Option<Vec<u8>>, WorkerRpcFailure> {
        let publication = {
            let streams = self.streams.lock().map_err(|_| failure())?;
            match &streams.get(id).ok_or_else(failure)?.scope {
                StreamScope::Retained {
                    scope: owner,
                    publication,
                } if owner == scope => publication.clone(),
                _ => return Err(failure()),
            }
        };
        self.read_scoped(
            &StreamScope::Retained {
                scope: scope.clone(),
                publication,
            },
            id,
            sequence,
            Some(now_unix_millis),
        )
    }
    fn read_scoped(
        &self,
        scope: &StreamScope,
        id: &LeaseId,
        sequence: u64,
        now_unix_millis: Option<u64>,
    ) -> Result<Option<Vec<u8>>, WorkerRpcFailure> {
        let mut streams = self.streams.lock().map_err(|_| failure())?;
        let now = Instant::now();
        streams.retain(|_, stream| stream.expires > now);
        let stream = streams.get_mut(id).ok_or_else(failure)?;
        if &stream.scope != scope {
            return Err(failure());
        }
        let ttl = match (&stream.scope, now_unix_millis) {
            (StreamScope::Live(_), None) => self.ttl,
            (StreamScope::Retained { publication, .. }, Some(utc))
                if utc >= publication.published_at_unix_millis()
                    && utc < publication.expires_at_unix_millis() =>
            {
                self.ttl.min(Duration::from_millis(
                    publication.expires_at_unix_millis() - utc,
                ))
            }
            _ => {
                streams.remove(id);
                return Err(failure());
            }
        };
        // A lost response fails the download; never silently skip a chunk on retry.
        if sequence != stream.next_sequence {
            return Err(failure());
        }
        match stream.reader.next_chunk() {
            Ok(Some(bytes)) if !bytes.is_empty() && bytes.len() <= 64 * 1024 => {
                stream.next_sequence = stream.next_sequence.checked_add(1).ok_or_else(failure)?;
                stream.expires = now + ttl;
                Ok(Some(bytes))
            }
            Ok(None) => {
                streams.remove(id);
                Ok(None)
            }
            _ => {
                streams.remove(id);
                Err(failure())
            }
        }
    }
    pub(super) fn close(
        &self,
        fence: &WorkerSessionFence,
        id: &LeaseId,
    ) -> Result<(), WorkerRpcFailure> {
        self.close_scoped(id, |scope| scope == &StreamScope::Live(fence.clone()))
    }
    pub(super) fn close_retained(
        &self,
        owner: &WorkerRetainedArtifactScope,
        id: &LeaseId,
    ) -> Result<(), WorkerRpcFailure> {
        self.close_scoped(
            id,
            |scope| matches!(scope,StreamScope::Retained{scope,..} if scope == owner),
        )
    }
    fn close_scoped(
        &self,
        id: &LeaseId,
        matches: impl FnOnce(&StreamScope) -> bool,
    ) -> Result<(), WorkerRpcFailure> {
        let mut streams = self.streams.lock().map_err(|_| failure())?;
        if streams
            .get(id)
            .is_some_and(|stream| !matches(&stream.scope))
        {
            return Err(failure());
        }
        streams.remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DependencyError;
    use browserd_core::{SessionId, TenantId};

    struct Reader(Option<Vec<u8>>);
    impl ArtifactReadStream for Reader {
        fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, DependencyError> {
            Ok(self.0.take())
        }
    }
    fn fence() -> WorkerSessionFence {
        WorkerSessionFence {
            tenant_id: TenantId::new(),
            session_id: SessionId::new(),
            worker_epoch: 1,
            placement_version: 1,
            session_incarnation: 1,
        }
    }

    #[test]
    fn stream_requires_exact_namespace_and_sequence_and_releases_capacity()
    -> Result<(), WorkerRpcFailure> {
        let streams = ArtifactStreams::new(1, Duration::from_secs(10));
        let owner = fence();
        let id = streams.open(owner.clone(), Box::new(Reader(Some(vec![1, 2]))))?;
        assert!(streams.open(owner.clone(), Box::new(Reader(None))).is_err());
        assert!(streams.read(&fence(), &id, 0).is_err());
        assert!(streams.close(&fence(), &id).is_err());
        assert!(streams.read(&owner, &id, 1).is_err());
        assert_eq!(streams.read(&owner, &id, 0)?, Some(vec![1, 2]));
        assert!(streams.read(&owner, &id, 0).is_err());
        assert_eq!(streams.read(&owner, &id, 1)?, None);
        assert!(streams.open(owner, Box::new(Reader(None))).is_ok());
        Ok(())
    }

    #[test]
    fn oversized_chunk_fails_and_expired_streams_release_their_readers()
    -> Result<(), WorkerRpcFailure> {
        let owner = fence();
        let streams = ArtifactStreams::new(1, Duration::from_secs(10));
        let id = streams.open(owner.clone(), Box::new(Reader(Some(vec![0; 65_537]))))?;
        assert!(streams.read(&owner, &id, 0).is_err());
        assert!(streams.open(owner.clone(), Box::new(Reader(None))).is_ok());
        let expired = ArtifactStreams::new(1, Duration::ZERO);
        let id = expired.open(owner.clone(), Box::new(Reader(None)))?;
        assert!(expired.read(&owner, &id, 0).is_err());
        assert!(expired.open(owner, Box::new(Reader(None))).is_ok());
        Ok(())
    }
    #[allow(clippy::expect_used)]
    fn retained(owner: &WorkerSessionFence) -> (WorkerRetainedArtifactScope, ArtifactPublication) {
        use browserd_artifacts::{
            ArtifactChecksum, ArtifactContentMetadata, ArtifactContentSource, ArtifactKey,
            ArtifactObjectGeneration,
        };
        use browserd_session::OwnershipFence;
        let worker_id = browserd_core::WorkerId::new("retained-worker").expect("worker");
        let scope = WorkerRetainedArtifactScope {
            worker_id: worker_id.clone(),
            worker_epoch: 5,
            tenant_id: owner.tenant_id.clone(),
            session_id: owner.session_id.clone(),
        };
        let publication = ArtifactPublication::new(
            ArtifactKey::new(
                owner.tenant_id.clone(),
                owner.session_id.clone(),
                browserd_core::ArtifactId::new(),
            ),
            OwnershipFence::new(worker_id, 1, 2, 3),
            ArtifactContentMetadata::new(
                2,
                ArtifactChecksum::new([3; 32]),
                "text/plain",
                ArtifactContentSource::Generated,
                "browserd-capture",
            )
            .expect("metadata"),
            ArtifactObjectGeneration::new([4; 32]),
            None,
            Some("retained.txt".to_owned()),
            1000,
            2000,
        )
        .expect("publication");
        (scope, publication)
    }
    #[test]
    #[allow(clippy::expect_used)]
    fn retained_and_live_tokens_share_capacity_but_never_authority() -> Result<(), WorkerRpcFailure>
    {
        let streams = ArtifactStreams::new(1, Duration::from_secs(60));
        let owner = fence();
        let (scope, publication) = retained(&owner);
        let id = streams.open_retained(
            scope.clone(),
            publication.clone(),
            Box::new(Reader(Some(vec![1, 2]))),
            1000,
        )?;
        assert!(streams.open(owner.clone(), Box::new(Reader(None))).is_err());
        assert!(streams.read(&owner, &id, 0).is_err());
        assert!(streams.close(&owner, &id).is_err());
        let mut foreign = scope.clone();
        foreign.worker_epoch = 6;
        assert!(streams.read_retained(&foreign, &id, 0, 1000).is_err());
        assert!(streams.close_retained(&foreign, &id).is_err());
        assert_eq!(
            streams.read_retained(&scope, &id, 0, 1000)?,
            Some(vec![1, 2])
        );
        assert!(streams.read_retained(&scope, &id, 0, 1000).is_err());
        assert_eq!(streams.read_retained(&scope, &id, 1, 1000)?, None);
        let live = streams.open(owner.clone(), Box::new(Reader(None)))?;
        assert!(streams.read_retained(&scope, &live, 0, 1000).is_err());
        assert!(streams.close_retained(&scope, &live).is_err());
        streams.close(&owner, &live)?;
        assert!(
            streams
                .open_retained(scope, publication, Box::new(Reader(None)), 1000)
                .is_ok()
        );
        Ok(())
    }
    #[test]
    #[allow(clippy::expect_used)]
    fn publication_expiry_prevents_chunk_and_releases_global_capacity()
    -> Result<(), WorkerRpcFailure> {
        let streams = ArtifactStreams::new(1, Duration::from_secs(60));
        let owner = fence();
        let (scope, publication) = retained(&owner);
        let id = streams.open_retained(
            scope.clone(),
            publication.clone(),
            Box::new(Reader(Some(vec![1, 2]))),
            1000,
        )?;
        assert!(
            streams
                .read_retained(&scope, &id, 0, publication.expires_at_unix_millis())
                .is_err()
        );
        assert!(streams.open(owner.clone(), Box::new(Reader(None))).is_ok());
        let shorter = ArtifactStreams::new(1, Duration::from_secs(60));
        let id = shorter.open_retained(scope.clone(), publication, Box::new(Reader(None)), 1999)?;
        std::thread::sleep(Duration::from_millis(3));
        assert!(shorter.read_retained(&scope, &id, 0, 1999).is_err());
        assert!(shorter.open(owner, Box::new(Reader(None))).is_ok());
        Ok(())
    }
}
