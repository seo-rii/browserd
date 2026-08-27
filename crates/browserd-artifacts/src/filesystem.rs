use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

use crate::{
    ArtifactChecksum, ArtifactKey, ArtifactMultipartStore, ArtifactStoreError,
    ArtifactWriteReceipt, MultipartUploadId,
};

const COMMIT_MAGIC: &[u8; 8] = b"BRDART01";
const COMMIT_METADATA_BYTES: usize = 64;
const MAX_VERIFIED_READ_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct FilesystemArtifactStore {
    root: Arc<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedArtifact {
    receipt: ArtifactWriteReceipt,
    bytes: Bytes,
}

impl VerifiedArtifact {
    #[must_use]
    pub const fn receipt(&self) -> &ArtifactWriteReceipt {
        &self.receipt
    }

    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        &self.bytes
    }
}

#[derive(Clone, Copy)]
struct CommitMetadata {
    upload_id: Uuid,
    size_bytes: u64,
    checksum: ArtifactChecksum,
}

impl FilesystemArtifactStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ArtifactStoreError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(ArtifactStoreError::new(
                "artifact root must be an absolute path",
            ));
        }
        let metadata = std::fs::symlink_metadata(root)
            .map_err(|error| store_error("inspect artifact root", error))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ArtifactStoreError::new(
                "artifact root must be a real directory",
            ));
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ArtifactStoreError::new(
                "artifact root must not be accessible by group or other users",
            ));
        }
        let root = root
            .canonicalize()
            .map_err(|error| store_error("canonicalize artifact root", error))?;
        for child in [".multipart", "objects"] {
            let path = root.join(child);
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                        .map_err(|error| store_error("secure artifact directory", error))?;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let child_metadata = std::fs::symlink_metadata(&path)
                        .map_err(|error| store_error("inspect artifact directory", error))?;
                    if !child_metadata.is_dir() || child_metadata.file_type().is_symlink() {
                        return Err(ArtifactStoreError::new(
                            "artifact store child must be a real directory",
                        ));
                    }
                    #[cfg(unix)]
                    if child_metadata.permissions().mode() & 0o077 != 0 {
                        return Err(ArtifactStoreError::new(
                            "artifact store child must not be accessible by group or other users",
                        ));
                    }
                }
                Err(error) => return Err(store_error("create artifact directory", error)),
            }
        }
        Ok(Self {
            root: Arc::new(root),
        })
    }

    pub async fn read_verified(
        &self,
        key: &ArtifactKey,
    ) -> Result<Option<VerifiedArtifact>, ArtifactStoreError> {
        let directory = self.object_path(key);
        let metadata = match read_commit_metadata(&directory).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(store_error("read committed artifact metadata", error)),
        };
        if metadata.size_bytes > MAX_VERIFIED_READ_BYTES {
            return Err(ArtifactStoreError::new(
                "artifact exceeds bounded verified read limit",
            ));
        }
        let (actual_size, actual_checksum) = inspect_data(&directory.join("data")).await?;
        if actual_size != metadata.size_bytes || actual_checksum != metadata.checksum {
            return Err(ArtifactStoreError::new(
                "committed artifact failed integrity verification",
            ));
        }
        let bytes = fs::read(directory.join("data"))
            .await
            .map_err(|error| store_error("read committed artifact", error))?;
        Ok(Some(VerifiedArtifact {
            receipt: ArtifactWriteReceipt {
                key: key.clone(),
                size_bytes: metadata.size_bytes,
                checksum: metadata.checksum,
            },
            bytes: Bytes::from(bytes),
        }))
    }

    fn stage_path(&self, upload_id: &MultipartUploadId) -> Result<PathBuf, ArtifactStoreError> {
        let upload_id = parse_upload_id(upload_id)?;
        Ok(self.root.join(".multipart").join(upload_id.to_string()))
    }

    fn object_path(&self, key: &ArtifactKey) -> PathBuf {
        self.root
            .join("objects")
            .join(key.tenant_id().to_string())
            .join(key.session_id().to_string())
            .join(key.artifact_id().to_string())
    }
}

impl ArtifactMultipartStore for FilesystemArtifactStore {
    async fn begin(&self, key: &ArtifactKey) -> Result<MultipartUploadId, ArtifactStoreError> {
        let upload_id = MultipartUploadId::new(Uuid::now_v7().to_string());
        let stage = self.stage_path(&upload_id)?;
        fs::create_dir(&stage)
            .await
            .map_err(|error| store_error("create multipart directory", error))?;
        #[cfg(unix)]
        fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|error| store_error("secure multipart directory", error))?;

        let binding = key_binding(key);
        let mut binding_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(stage.join("key"))
            .await
            .map_err(|error| store_error("create multipart key binding", error))?;
        binding_file
            .write_all(binding.as_bytes())
            .await
            .map_err(|error| store_error("write multipart key binding", error))?;
        binding_file
            .sync_all()
            .await
            .map_err(|error| store_error("sync multipart key binding", error))?;
        let data_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(stage.join("data"))
            .await
            .map_err(|error| store_error("create multipart data", error))?;
        data_file
            .sync_all()
            .await
            .map_err(|error| store_error("sync multipart data", error))?;
        sync_directory(&stage).await?;
        sync_directory(&self.root.join(".multipart")).await?;
        Ok(upload_id)
    }

    async fn append(
        &self,
        upload_id: &MultipartUploadId,
        chunk: Bytes,
    ) -> Result<(), ArtifactStoreError> {
        let stage = self.stage_path(upload_id)?;
        let mut data = OpenOptions::new()
            .append(true)
            .open(stage.join("data"))
            .await
            .map_err(|error| store_error("open multipart data", error))?;
        data.write_all(&chunk)
            .await
            .map_err(|error| store_error("append multipart data", error))?;
        data.sync_data()
            .await
            .map_err(|error| store_error("sync multipart data", error))
    }

    async fn complete_verified(
        &self,
        upload_id: &MultipartUploadId,
        receipt: &ArtifactWriteReceipt,
    ) -> Result<(), ArtifactStoreError> {
        let parsed_upload_id = parse_upload_id(upload_id)?;
        let stage = self.stage_path(upload_id)?;
        let destination = self.object_path(receipt.key());
        if !fs::try_exists(&stage)
            .await
            .map_err(|error| store_error("inspect multipart directory", error))?
        {
            let committed = read_commit_metadata(&destination)
                .await
                .map_err(|error| store_error("read completion replay metadata", error))?;
            if committed.upload_id == parsed_upload_id
                && committed.size_bytes == receipt.size_bytes()
                && committed.checksum == *receipt.checksum()
            {
                return Ok(());
            }
            return Err(ArtifactStoreError::new(
                "multipart upload is not available for completion",
            ));
        }

        let binding = fs::read_to_string(stage.join("key"))
            .await
            .map_err(|error| store_error("read multipart key binding", error))?;
        if binding != key_binding(receipt.key()) {
            return Err(ArtifactStoreError::new(
                "multipart upload belongs to another artifact",
            ));
        }
        let (actual_size, actual_checksum) = inspect_data(&stage.join("data")).await?;
        if actual_size != receipt.size_bytes() || actual_checksum != *receipt.checksum() {
            return Err(ArtifactStoreError::new(
                "multipart completion receipt does not match stored bytes",
            ));
        }

        let mut encoded = [0_u8; COMMIT_METADATA_BYTES];
        encoded[..8].copy_from_slice(COMMIT_MAGIC);
        encoded[8..24].copy_from_slice(parsed_upload_id.as_bytes());
        encoded[24..32].copy_from_slice(&receipt.size_bytes().to_be_bytes());
        encoded[32..64].copy_from_slice(receipt.checksum().as_bytes());
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(stage.join("receipt"))
            .await
        {
            Ok(mut metadata_file) => {
                metadata_file
                    .write_all(&encoded)
                    .await
                    .map_err(|error| store_error("write artifact receipt", error))?;
                metadata_file
                    .sync_all()
                    .await
                    .map_err(|error| store_error("sync artifact receipt", error))?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = read_commit_metadata(&stage)
                    .await
                    .map_err(|error| store_error("read staged artifact receipt", error))?;
                if existing.upload_id != parsed_upload_id
                    || existing.size_bytes != receipt.size_bytes()
                    || existing.checksum != *receipt.checksum()
                {
                    return Err(ArtifactStoreError::new(
                        "staged artifact receipt conflicts with completion",
                    ));
                }
            }
            Err(error) => return Err(store_error("create artifact receipt", error)),
        }

        let tenant_directory = self
            .root
            .join("objects")
            .join(receipt.key().tenant_id().to_string());
        let session_directory = tenant_directory.join(receipt.key().session_id().to_string());
        for directory in [&tenant_directory, &session_directory] {
            match fs::create_dir(directory).await {
                Ok(()) => {
                    #[cfg(unix)]
                    fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                        .await
                        .map_err(|error| store_error("secure artifact namespace", error))?;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(directory)
                        .await
                        .map_err(|error| store_error("inspect artifact namespace", error))?;
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        return Err(ArtifactStoreError::new(
                            "artifact namespace must be a real directory",
                        ));
                    }
                }
                Err(error) => return Err(store_error("create artifact namespace", error)),
            }
        }
        sync_directory(&stage).await?;
        sync_directory(&tenant_directory).await?;
        sync_directory(&self.root.join("objects")).await?;

        match fs::rename(&stage, &destination).await {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AlreadyExists | io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                let committed = read_commit_metadata(&destination)
                    .await
                    .map_err(|error| store_error("read committed artifact receipt", error))?;
                if committed.upload_id == parsed_upload_id
                    && committed.size_bytes == receipt.size_bytes()
                    && committed.checksum == *receipt.checksum()
                {
                    Ok(())
                } else {
                    Err(ArtifactStoreError::new(
                        "artifact was already committed by another upload",
                    ))
                }
            }
            Err(error) => Err(store_error("commit multipart artifact", error)),
        }
    }

    async fn abort(&self, upload_id: &MultipartUploadId) -> Result<(), ArtifactStoreError> {
        let stage = self.stage_path(upload_id)?;
        if !fs::try_exists(&stage)
            .await
            .map_err(|error| store_error("inspect multipart abort target", error))?
        {
            return Ok(());
        }
        for name in ["data", "key", "receipt"] {
            match fs::remove_file(stage.join(name)).await {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(store_error("remove multipart file", error)),
            }
        }
        fs::remove_dir(stage)
            .await
            .map_err(|error| store_error("remove multipart directory", error))
    }
}

fn parse_upload_id(upload_id: &MultipartUploadId) -> Result<Uuid, ArtifactStoreError> {
    let parsed = Uuid::parse_str(upload_id.as_str())
        .map_err(|_| ArtifactStoreError::new("multipart upload ID is invalid"))?;
    if parsed.get_version() != Some(uuid::Version::SortRand)
        || parsed.hyphenated().to_string() != upload_id.as_str()
    {
        return Err(ArtifactStoreError::new("multipart upload ID is invalid"));
    }
    Ok(parsed)
}

fn key_binding(key: &ArtifactKey) -> String {
    format!(
        "{}\n{}\n{}\n",
        key.tenant_id(),
        key.session_id(),
        key.artifact_id()
    )
}

async fn read_commit_metadata(directory: &Path) -> io::Result<CommitMetadata> {
    let encoded = fs::read(directory.join("receipt")).await?;
    if encoded.len() != COMMIT_METADATA_BYTES || &encoded[..8] != COMMIT_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid artifact receipt",
        ));
    }
    let upload_id = Uuid::from_slice(&encoded[8..24])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid upload UUID"))?;
    let size_bytes = u64::from_be_bytes(
        encoded[24..32]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid artifact size"))?,
    );
    let checksum = ArtifactChecksum::new(
        encoded[32..64]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid checksum"))?,
    );
    Ok(CommitMetadata {
        upload_id,
        size_bytes,
        checksum,
    })
}

async fn inspect_data(path: &Path) -> Result<(u64, ArtifactChecksum), ArtifactStoreError> {
    let file = fs::File::open(path)
        .await
        .map_err(|error| store_error("open artifact data for verification", error))?;
    let mut reader = BufReader::new(file);
    let mut buffer = [0_u8; 64 * 1024];
    let mut size_bytes = 0_u64;
    let mut hasher = Sha256::new();
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|error| store_error("read artifact data for verification", error))?;
        if read == 0 {
            break;
        }
        size_bytes = size_bytes
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| ArtifactStoreError::new("artifact size exceeds u64"))?,
            )
            .ok_or_else(|| ArtifactStoreError::new("artifact size exceeds u64"))?;
        hasher.update(&buffer[..read]);
    }
    Ok((size_bytes, ArtifactChecksum::new(hasher.finalize().into())))
}

async fn sync_directory(path: &Path) -> Result<(), ArtifactStoreError> {
    let directory = fs::File::open(path)
        .await
        .map_err(|error| store_error("open artifact directory for sync", error))?;
    directory
        .sync_all()
        .await
        .map_err(|error| store_error("sync artifact directory", error))
}

fn store_error(operation: &str, error: io::Error) -> ArtifactStoreError {
    ArtifactStoreError::new(format!("{operation}: {error}"))
}
