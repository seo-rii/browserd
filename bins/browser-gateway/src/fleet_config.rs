//! Immutable private configuration: socket authority is supplied only by the operator.
use crate::{GatewayConfigurationError, GatewayFleetInventory, GatewayFleetPeer};
use browserd_coordination::GatewayFleetAdmissionConfig;
use browserd_core::WorkerId;
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use nix::unistd::Uid;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayFleetPeerConfig {
    worker_id: WorkerId,
    socket_path: PathBuf,
    peer_uid: u32,
    expected_worker_epoch: u64,
}
impl GatewayFleetPeerConfig {
    pub fn worker_id(&self) -> &WorkerId {
        &self.worker_id
    }
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
    pub const fn peer_uid(&self) -> u32 {
        self.peer_uid
    }
    pub const fn expected_worker_epoch(&self) -> u64 {
        self.expected_worker_epoch
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayFleetConfig {
    schema_version: u8,
    admission: GatewayFleetAdmissionConfig,
    peers: Vec<GatewayFleetPeerConfig>,
}
impl GatewayFleetConfig {
    pub fn load(path: &Path) -> Result<Self, GatewayConfigurationError> {
        let bad = || GatewayConfigurationError::InvalidWorkerPlacement;
        let parent = path
            .parent()
            .filter(|parent| parent.is_absolute())
            .ok_or_else(bad)?;
        let metadata = std::fs::symlink_metadata(parent).map_err(|_| bad())?;
        if parent.canonicalize().map_err(|_| bad())? != parent
            || !metadata.is_dir()
            || metadata.uid() != Uid::effective().as_raw()
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(bad());
        }
        let fd = open(
            path,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| bad())?;
        let mut file = File::from(fd);
        let before = file.metadata().map_err(|_| bad())?;
        if !before.is_file()
            || before.nlink() != 1
            || before.uid() != Uid::effective().as_raw()
            || !matches!(before.mode() & 0o777, 0o400 | 0o600)
            || before.len() > 1_048_576
        {
            return Err(bad());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|_| bad())?;
        let after = file.metadata().map_err(|_| bad())?;
        let linked = std::fs::symlink_metadata(path).map_err(|_| bad())?;
        if bytes.len() > 1_048_576
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || after.dev() != linked.dev()
            || after.ino() != linked.ino()
            || after.nlink() != 1
        {
            return Err(bad());
        }
        let value: Self = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), GatewayConfigurationError> {
        let bad = || GatewayConfigurationError::InvalidWorkerPlacement;
        if self.schema_version != 1
            || self.peers.is_empty()
            || self.peers.len() > 256
            || self.peers.len() != self.admission.workers().len()
        {
            return Err(bad());
        }
        let mut workers = BTreeSet::new();
        let mut sockets = BTreeSet::new();
        for peer in &self.peers {
            let endpoint = peer.socket_path.to_str().ok_or_else(bad)?;
            if !peer.socket_path.is_absolute()
                || peer.socket_path.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
                || peer.expected_worker_epoch == 0
                || !workers.insert(peer.worker_id.clone())
                || !sockets.insert(peer.socket_path.clone())
                || !self.admission.workers().iter().any(|worker| {
                    worker.worker_id() == &peer.worker_id && worker.endpoint() == endpoint
                })
            {
                return Err(bad());
            }
        }
        Ok(())
    }
    pub fn admission(&self) -> &GatewayFleetAdmissionConfig {
        &self.admission
    }
    pub fn peers(&self) -> &[GatewayFleetPeerConfig] {
        &self.peers
    }
    pub fn inventory<C>(
        &self,
        clients: Vec<Arc<C>>,
    ) -> Result<GatewayFleetInventory<C>, GatewayConfigurationError> {
        if clients.len() != self.peers.len() {
            return Err(GatewayConfigurationError::InvalidWorkerPlacement);
        }
        let peers = self
            .peers
            .iter()
            .zip(clients)
            .map(|(peer, client)| {
                GatewayFleetPeer::new(
                    peer.worker_id.clone(),
                    peer.socket_path
                        .to_str()
                        .ok_or(GatewayConfigurationError::InvalidWorkerPlacement)?
                        .to_owned(),
                    peer.expected_worker_epoch,
                    client,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        GatewayFleetInventory::new(Arc::new(self.admission.clone()), peers)
    }
}
