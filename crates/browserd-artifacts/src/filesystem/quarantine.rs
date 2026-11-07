//! Private verified multipart seals. These objects never enter the public object namespace.
use super::*;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;

use nix::fcntl::{AtFlags, openat, renameat};
use nix::sys::stat::{fstatat, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};

fn failure() -> ArtifactObjectError {
    ArtifactObjectError::IntegrityMismatch
}
fn private(file: &File, directory: bool) -> Result<(), ArtifactObjectError> {
    let metadata = file.metadata().map_err(|_| failure())?;
    if metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o777 != if directory { 0o700 } else { 0o600 }
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.nlink() != 1
        }
    {
        return Err(failure());
    }
    Ok(())
}
fn directory(parent: &File, name: &str, create: bool) -> Result<Option<File>, ArtifactObjectError> {
    if create {
        match mkdirat(parent.as_fd(), name, Mode::from_bits_truncate(0o700)) {
            Ok(()) => parent.sync_all().map_err(|_| failure())?,
            Err(nix::errno::Errno::EEXIST) => {}
            Err(_) => return Err(failure()),
        }
    }
    let file = match openat(
        parent.as_fd(),
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(_) => return Err(failure()),
    };
    private(&file, true)?;
    Ok(Some(file))
}
fn regular(parent: &File, name: &str, flags: OFlag) -> Result<File, ArtifactObjectError> {
    let file = File::from(
        openat(
            parent.as_fd(),
            name,
            flags | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| failure())?,
    );
    private(&file, false)?;
    Ok(file)
}
fn root(store: &FilesystemArtifactStore) -> Result<&File, ArtifactObjectError> {
    private(&store.quarantine_root, true)?;
    let linked =
        std::fs::symlink_metadata(store.root.join(".quarantine")).map_err(|_| failure())?;
    let pinned = store.quarantine_root.metadata().map_err(|_| failure())?;
    if linked.dev() != pinned.dev()
        || linked.ino() != pinned.ino()
        || linked.file_type().is_symlink()
    {
        return Err(failure());
    }
    Ok(&store.quarantine_root)
}
fn parent(
    store: &FilesystemArtifactStore,
    key: &ArtifactKey,
    create: bool,
) -> Result<Option<File>, ArtifactObjectError> {
    let mut directory = root(store)?.try_clone().map_err(|_| failure())?;
    for name in [
        key.tenant_id().to_string(),
        key.session_id().to_string(),
        key.artifact_id().to_string(),
    ] {
        let Some(child) = self::directory(&directory, &name, create)? else {
            return Ok(None);
        };
        directory = child;
    }
    Ok(Some(directory))
}
fn metadata(dir: &File, key: &ArtifactKey) -> Result<ArtifactWriteReceipt, ArtifactObjectError> {
    let mut binding = regular(dir, "key", OFlag::O_RDONLY)?;
    if binding.metadata().map_err(|_| failure())?.len() > 256 {
        return Err(failure());
    }
    let mut text = String::new();
    binding.read_to_string(&mut text).map_err(|_| failure())?;
    if text != key_binding(key) {
        return Err(failure());
    }
    let mut file = regular(dir, "receipt", OFlag::O_RDONLY)?;
    if file.metadata().map_err(|_| failure())?.len() != COMMIT_METADATA_BYTES as u64 {
        return Err(failure());
    }
    let mut encoded = [0; COMMIT_METADATA_BYTES];
    file.read_exact(&mut encoded).map_err(|_| failure())?;
    if &encoded[..8] != COMMIT_MAGIC {
        return Err(failure());
    }
    let upload = Uuid::from_slice(&encoded[8..24]).map_err(|_| failure())?;
    if upload.is_nil() || !matches!(upload.get_version_num(), 4 | 7) {
        return Err(failure());
    }
    Ok(ArtifactWriteReceipt {
        key: key.clone(),
        size_bytes: u64::from_be_bytes(encoded[24..32].try_into().map_err(|_| failure())?),
        checksum: ArtifactChecksum::new(encoded[32..64].try_into().map_err(|_| failure())?),
        object_generation: object_generation_for_upload_id(&upload.to_string()),
    })
}
fn verify_data(dir: &File, receipt: &ArtifactWriteReceipt) -> Result<(), ArtifactObjectError> {
    let mut data = regular(dir, "data", OFlag::O_RDONLY)?;
    let before = data.metadata().map_err(|_| failure())?;
    if before.len() != receipt.size_bytes() {
        return Err(failure());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut size = 0u64;
    loop {
        let count = data.read(&mut buffer).map_err(|_| failure())?;
        if count == 0 {
            break;
        }
        size = size.checked_add(count as u64).ok_or_else(failure)?;
        if size > receipt.size_bytes() {
            return Err(failure());
        }
        digest.update(&buffer[..count]);
    }
    let after = data.metadata().map_err(|_| failure())?;
    let linked =
        fstatat(dir.as_fd(), "data", AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| failure())?;
    if size != receipt.size_bytes()
        || &digest.finalize()[..] != receipt.checksum().as_bytes()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || linked.st_ino != after.ino()
        || linked.st_dev != after.dev()
        || before.len() != after.len()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.mtime() != after.mtime()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(failure());
    }
    data.sync_all().map_err(|_| failure())
}
fn generation_name(generation: ArtifactObjectGeneration) -> String {
    encode_generation(generation)
}
fn deleted_name(generation: ArtifactObjectGeneration) -> String {
    format!(".deleted-{}", generation_name(generation))
}
fn inspect(
    store: &FilesystemArtifactStore,
    key: &ArtifactKey,
    generation: ArtifactObjectGeneration,
) -> Result<Option<(ArtifactWriteReceipt, bool)>, ArtifactObjectError> {
    let Some(parent) = parent(store, key, false)? else {
        return Ok(None);
    };
    let live = directory(&parent, &generation_name(generation), false)?;
    let deleted = directory(&parent, &deleted_name(generation), false)?;
    if live.is_some() && deleted.is_some() {
        return Err(failure());
    }
    let (directory, deleted) = match (live, deleted) {
        (Some(directory), None) => (directory, false),
        (None, Some(directory)) => (directory, true),
        _ => return Ok(None),
    };
    let receipt = metadata(&directory, key)?;
    if receipt.object_generation() != generation {
        return Err(ArtifactObjectError::GenerationMismatch);
    }
    if !deleted {
        verify_data(&directory, &receipt)?;
    }
    Ok(Some((receipt, deleted)))
}

// The exclusive stable-root lock prevents a new seal from racing this empty-directory GC.
fn prune_empty_parents(
    store: &FilesystemArtifactStore,
    key: &ArtifactKey,
    expected: &File,
) -> Result<(), ArtifactObjectError> {
    use std::os::fd::AsRawFd;
    let root = root(store)?;
    let tenant_name = key.tenant_id().to_string();
    let session_name = key.session_id().to_string();
    let artifact_name = key.artifact_id().to_string();
    let tenant = directory(root, &tenant_name, false)?.ok_or_else(failure)?;
    let session = directory(&tenant, &session_name, false)?.ok_or_else(failure)?;
    let artifact = directory(&session, &artifact_name, false)?.ok_or_else(failure)?;
    let previous = expected.metadata().map_err(|_| failure())?;
    let current = artifact.metadata().map_err(|_| failure())?;
    if previous.ino() != current.ino() || previous.dev() != current.dev() {
        return Err(failure());
    }
    for (parent, child, name, allow_lock) in [
        (&session, &artifact, artifact_name.as_str(), true),
        (&tenant, &session, session_name.as_str(), false),
        (root, &tenant, tenant_name.as_str(), false),
    ] {
        let mut entries = std::fs::read_dir(format!("/proc/self/fd/{}", child.as_raw_fd()))
            .map_err(|_| failure())?;
        if let Some(entry) = entries.next() {
            let entry = entry.map_err(|_| failure())?;
            if !allow_lock || entry.file_name() != "lock" || entries.next().is_some() {
                break;
            }
            let _lock = regular(child, "lock", OFlag::O_RDONLY)?;
            unlinkat(child.as_fd(), "lock", UnlinkatFlags::NoRemoveDir).map_err(|_| failure())?;
            child.sync_all().map_err(|_| failure())?;
        }
        let linked =
            fstatat(parent.as_fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|_| failure())?;
        let pinned = child.metadata().map_err(|_| failure())?;
        if linked.st_ino != pinned.ino() || linked.st_dev != pinned.dev() {
            return Err(failure());
        }
        unlinkat(parent.as_fd(), name, UnlinkatFlags::RemoveDir).map_err(|_| failure())?;
        parent.sync_all().map_err(|_| failure())?;
    }
    Ok(())
}

impl FilesystemArtifactStore {
    pub async fn begin_quarantine(
        &self,
        key: &ArtifactKey,
    ) -> Result<MultipartUploadId, ArtifactStoreError> {
        let upload = self.begin(key).await?;
        let store = self.clone();
        let private_upload = upload.clone();
        tokio::task::spawn_blocking(move || {
            let multipart = File::from(
                open(
                    &store.root.join(".multipart"),
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| failure())?,
            );
            let stage =
                directory(&multipart, private_upload.as_str(), false)?.ok_or_else(failure)?;
            stage.lock().map_err(|_| failure())?;
            for name in ["key", "data", "lock"] {
                let file = File::from(
                    openat(
                        stage.as_fd(),
                        name,
                        OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| failure())?,
                );
                let metadata = file.metadata().map_err(|_| failure())?;
                if !metadata.is_file()
                    || metadata.nlink() != 1
                    || metadata.uid() != nix::unistd::Uid::effective().as_raw()
                {
                    return Err(failure());
                }
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|_| failure())?;
                file.sync_all().map_err(|_| failure())?;
            }
            stage.sync_all().map_err(|_| failure())
        })
        .await
        .map_err(|_| {
            ArtifactStoreError::completion_uncertain("private multipart begin task failed")
        })?
        .map_err(|_| {
            ArtifactStoreError::completion_uncertain("private multipart stage could not be secured")
        })?;
        Ok(upload)
    }
    pub async fn complete_quarantine_verified(
        &self,
        upload: &MultipartUploadId,
        receipt: &ArtifactWriteReceipt,
    ) -> Result<(), ArtifactStoreError> {
        let store = self.clone();
        let upload = upload.clone();
        let receipt = receipt.clone();
        tokio::task::spawn_blocking(move || {
            let _root = lock_stable_deleted_root(
                &store.root.join(".deleted"),
                store.deleted_root_identity,
                false,
            )?;
            let upload_id = parse_upload_id(&upload)?;
            if receipt.object_generation() != object_generation_for_upload_id(upload.as_str()) {
                return Err(failure());
            }
            let parent = parent(&store, receipt.key(), true)?.ok_or_else(failure)?;
            let lock = regular(&parent, "lock", OFlag::O_RDWR | OFlag::O_CREAT)?;
            lock.lock().map_err(|_| failure())?;
            if let Some((sealed, deleted)) =
                inspect(&store, receipt.key(), receipt.object_generation())?
            {
                if sealed != receipt || deleted {
                    return Err(failure());
                }
                parent.sync_all().map_err(|_| failure())?;
                return Ok(());
            }
            let multipart = File::from(
                open(
                    &store.root.join(".multipart"),
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| failure())?,
            );
            private(&multipart, true)?;
            let stage =
                directory(&multipart, &upload_id.to_string(), false)?.ok_or_else(failure)?;
            stage.lock().map_err(|_| failure())?;
            verify_data(&stage, &receipt)?;
            let mut encoded = [0; COMMIT_METADATA_BYTES];
            encoded[..8].copy_from_slice(COMMIT_MAGIC);
            encoded[8..24].copy_from_slice(upload_id.as_bytes());
            encoded[24..32].copy_from_slice(&receipt.size_bytes().to_be_bytes());
            encoded[32..].copy_from_slice(receipt.checksum().as_bytes());
            match fstatat(stage.as_fd(), "receipt", AtFlags::AT_SYMLINK_NOFOLLOW) {
                Ok(_) => {
                    if metadata(&stage, receipt.key())? != receipt {
                        return Err(failure());
                    }
                }
                Err(nix::errno::Errno::ENOENT) => {
                    if fstatat(
                        stage.as_fd(),
                        "receipt.pending",
                        AtFlags::AT_SYMLINK_NOFOLLOW,
                    )
                    .is_ok()
                    {
                        let _pending = regular(&stage, "receipt.pending", OFlag::O_RDONLY)?;
                        unlinkat(stage.as_fd(), "receipt.pending", UnlinkatFlags::NoRemoveDir)
                            .map_err(|_| failure())?;
                    }
                    let mut pending = regular(
                        &stage,
                        "receipt.pending",
                        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
                    )?;
                    pending
                        .write_all(&encoded)
                        .and_then(|()| pending.sync_all())
                        .map_err(|_| failure())?;
                    renameat(stage.as_fd(), "receipt.pending", stage.as_fd(), "receipt")
                        .map_err(|_| failure())?;
                }
                Err(_) => return Err(failure()),
            }
            if metadata(&stage, receipt.key())? != receipt {
                return Err(failure());
            }
            stage.sync_all().map_err(|_| failure())?;
            renameat(
                multipart.as_fd(),
                upload_id.to_string().as_str(),
                parent.as_fd(),
                generation_name(receipt.object_generation()).as_str(),
            )
            .map_err(|_| failure())?;
            parent
                .sync_all()
                .and_then(|()| multipart.sync_all())
                .map_err(|_| failure())
        })
        .await
        .map_err(|_| ArtifactStoreError::completion_uncertain("private seal task failed"))?
        .map_err(|_| {
            ArtifactStoreError::completion_uncertain("private seal was not positively synchronized")
        })
    }
    pub async fn inspect_quarantine(
        &self,
        namespace: &ArtifactNamespace,
        key: &ArtifactKey,
        generation: ArtifactObjectGeneration,
    ) -> Result<Option<(ArtifactWriteReceipt, bool)>, ArtifactObjectError> {
        namespace
            .authorize(key)
            .map_err(|_| ArtifactObjectError::NamespaceDenied)?;
        let store = self.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            let _root = lock_stable_deleted_root(
                &store.root.join(".deleted"),
                store.deleted_root_identity,
                false,
            )?;
            inspect(&store, &key, generation)
        })
        .await
        .map_err(|_| failure())?
    }
    pub async fn delete_quarantine_exact(
        &self,
        namespace: &ArtifactNamespace,
        key: &ArtifactKey,
        generation: ArtifactObjectGeneration,
    ) -> Result<ArtifactDeleteOutcome, ArtifactObjectError> {
        namespace
            .authorize(key)
            .map_err(|_| ArtifactObjectError::NamespaceDenied)?;
        let store = self.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            let _root = lock_stable_deleted_root(
                &store.root.join(".deleted"),
                store.deleted_root_identity,
                false,
            )?;
            let parent = parent(&store, &key, false)?.ok_or(ArtifactObjectError::NotAvailable)?;
            let lock = regular(&parent, "lock", OFlag::O_RDWR | OFlag::O_CREAT)?;
            lock.lock().map_err(|_| failure())?;
            let Some((receipt, was_deleted)) = inspect(&store, &key, generation)? else {
                return Err(ArtifactObjectError::NotAvailable);
            };
            if !was_deleted {
                renameat(
                    parent.as_fd(),
                    generation_name(generation).as_str(),
                    parent.as_fd(),
                    deleted_name(generation).as_str(),
                )
                .map_err(|_| failure())?;
                parent.sync_all().map_err(|_| failure())?;
            }
            let tombstone =
                directory(&parent, &deleted_name(generation), false)?.ok_or_else(failure)?;
            match fstatat(tombstone.as_fd(), "data", AtFlags::AT_SYMLINK_NOFOLLOW) {
                Ok(_) => {
                    verify_data(&tombstone, &receipt)?;
                    let _data = regular(&tombstone, "data", OFlag::O_RDONLY)?;
                    unlinkat(tombstone.as_fd(), "data", UnlinkatFlags::NoRemoveDir)
                        .map_err(|_| failure())?;
                }
                Err(nix::errno::Errno::ENOENT) => {}
                Err(_) => return Err(failure()),
            }
            tombstone
                .sync_all()
                .and_then(|()| parent.sync_all())
                .map_err(|_| failure())?;
            let current = self::parent(&store, &key, false)?.ok_or_else(failure)?;
            let expected = parent.metadata().map_err(|_| failure())?;
            let current = current.metadata().map_err(|_| failure())?;
            if expected.ino() != current.ino() || expected.dev() != current.dev() {
                return Err(failure());
            }
            Ok(if was_deleted {
                ArtifactDeleteOutcome::AlreadyDeleted
            } else {
                ArtifactDeleteOutcome::Deleted
            })
        })
        .await
        .map_err(|_| failure())?
    }
    pub async fn quarantine_inventory(
        &self,
        maximum: usize,
    ) -> Result<Vec<(ArtifactWriteReceipt, bool)>, ArtifactObjectError> {
        if maximum == 0 {
            return Err(ArtifactObjectError::InvalidBounds);
        }
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            use std::os::fd::AsRawFd;
            let _root = lock_stable_deleted_root(
                &store.root.join(".deleted"),
                store.deleted_root_identity,
                false,
            )?;
            let pinned = root(&store)?;
            let mut found = Vec::new();
            let mut examined = 0usize;
            let max_entries = maximum
                .checked_mul(16)
                .and_then(|n| n.checked_add(64))
                .ok_or_else(failure)?;
            for tenant in std::fs::read_dir(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
                .map_err(|_| failure())?
            {
                examined = examined.checked_add(1).ok_or_else(failure)?;
                if examined > max_entries {
                    return Err(failure());
                }
                let tenant = tenant.map_err(|_| failure())?;
                let name = tenant.file_name().into_string().map_err(|_| failure())?;
                let tenant_id: TenantId = name.parse().map_err(|_| failure())?;
                if tenant_id.to_string() != name {
                    return Err(failure());
                }
                let tenant_dir = directory(pinned, &name, false)?.ok_or_else(failure)?;
                for session in
                    std::fs::read_dir(format!("/proc/self/fd/{}", tenant_dir.as_raw_fd()))
                        .map_err(|_| failure())?
                {
                    examined = examined.checked_add(1).ok_or_else(failure)?;
                    if examined > max_entries {
                        return Err(failure());
                    }
                    let session = session.map_err(|_| failure())?;
                    let name = session.file_name().into_string().map_err(|_| failure())?;
                    let session_id: SessionId = name.parse().map_err(|_| failure())?;
                    if session_id.to_string() != name {
                        return Err(failure());
                    }
                    let session_dir = directory(&tenant_dir, &name, false)?.ok_or_else(failure)?;
                    for artifact in
                        std::fs::read_dir(format!("/proc/self/fd/{}", session_dir.as_raw_fd()))
                            .map_err(|_| failure())?
                    {
                        examined = examined.checked_add(1).ok_or_else(failure)?;
                        if examined > max_entries {
                            return Err(failure());
                        }
                        let artifact = artifact.map_err(|_| failure())?;
                        let name = artifact.file_name().into_string().map_err(|_| failure())?;
                        let artifact_id: ArtifactId = name.parse().map_err(|_| failure())?;
                        if artifact_id.to_string() != name {
                            return Err(failure());
                        }
                        let artifact_dir =
                            directory(&session_dir, &name, false)?.ok_or_else(failure)?;
                        let key =
                            ArtifactKey::new(tenant_id.clone(), session_id.clone(), artifact_id);
                        for generation in
                            std::fs::read_dir(format!("/proc/self/fd/{}", artifact_dir.as_raw_fd()))
                                .map_err(|_| failure())?
                        {
                            examined = examined.checked_add(1).ok_or_else(failure)?;
                            if examined > max_entries {
                                return Err(failure());
                            }
                            let generation = generation.map_err(|_| failure())?;
                            let name = generation
                                .file_name()
                                .into_string()
                                .map_err(|_| failure())?;
                            if name == "lock" {
                                let _lock = regular(&artifact_dir, &name, OFlag::O_RDONLY)?;
                                continue;
                            }
                            let token = name.strip_prefix(".deleted-").unwrap_or(&name);
                            if token.len() != 64
                                || !token
                                    .bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                            {
                                return Err(failure());
                            }
                            let mut decoded = [0; 32];
                            for (index, byte) in decoded.iter_mut().enumerate() {
                                *byte = u8::from_str_radix(&token[index * 2..index * 2 + 2], 16)
                                    .map_err(|_| failure())?;
                            }
                            let generation = ArtifactObjectGeneration::new(decoded);
                            let value = inspect(&store, &key, generation)?.ok_or_else(failure)?;
                            if found.len() >= maximum {
                                return Err(failure());
                            }
                            found.push(value);
                        }
                    }
                }
            }
            root(&store)?;
            Ok(found)
        })
        .await
        .map_err(|_| failure())?
    }
    pub async fn prune_quarantine_delete_receipt(
        &self,
        namespace: &ArtifactNamespace,
        key: &ArtifactKey,
        generation: ArtifactObjectGeneration,
    ) -> Result<(), ArtifactObjectError> {
        namespace
            .authorize(key)
            .map_err(|_| ArtifactObjectError::NamespaceDenied)?;
        let store = self.clone();
        let key = key.clone();
        tokio::task::spawn_blocking(move || {
            let _root = lock_stable_deleted_root(
                &store.root.join(".deleted"),
                store.deleted_root_identity,
                true,
            )?;
            let Some(parent) = parent(&store, &key, false)? else {
                return Ok(());
            };
            let Some(tombstone) = directory(&parent, &deleted_name(generation), false)? else {
                return prune_empty_parents(&store, &key, &parent);
            };
            match fstatat(tombstone.as_fd(), "receipt", AtFlags::AT_SYMLINK_NOFOLLOW) {
                Ok(_) => {
                    if metadata(&tombstone, &key)?.object_generation() != generation {
                        return Err(ArtifactObjectError::GenerationMismatch);
                    }
                }
                Err(nix::errno::Errno::ENOENT) => {}
                Err(_) => return Err(failure()),
            }
            if !matches!(
                fstatat(tombstone.as_fd(), "data", AtFlags::AT_SYMLINK_NOFOLLOW),
                Err(nix::errno::Errno::ENOENT)
            ) {
                return Err(failure());
            }
            for name in ["receipt", "key", "lock"] {
                match fstatat(tombstone.as_fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW) {
                    Ok(_) => {
                        let _file = regular(&tombstone, name, OFlag::O_RDONLY)?;
                        unlinkat(tombstone.as_fd(), name, UnlinkatFlags::NoRemoveDir)
                            .map_err(|_| failure())?;
                    }
                    Err(nix::errno::Errno::ENOENT) => {}
                    Err(_) => return Err(failure()),
                }
            }
            tombstone.sync_all().map_err(|_| failure())?;
            unlinkat(
                parent.as_fd(),
                deleted_name(generation).as_str(),
                UnlinkatFlags::RemoveDir,
            )
            .map_err(|_| failure())?;
            parent.sync_all().map_err(|_| failure())?;
            prune_empty_parents(&store, &key, &parent)
        })
        .await
        .map_err(|_| failure())?
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, FilesystemArtifactStore, ArtifactKey) {
        let root = tempfile::tempdir().expect("private root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("root mode");
        let store = FilesystemArtifactStore::open(root.path()).expect("filesystem");
        (
            root,
            store,
            ArtifactKey::new(TenantId::new(), SessionId::new(), ArtifactId::new()),
        )
    }
    async fn stage(
        store: &FilesystemArtifactStore,
        key: &ArtifactKey,
        bytes: &[u8],
    ) -> (MultipartUploadId, ArtifactWriteReceipt) {
        let upload = store.begin_quarantine(key).await.expect("private begin");
        store
            .append(&upload, Bytes::copy_from_slice(bytes))
            .await
            .expect("append");
        let receipt = ArtifactWriteReceipt {
            key: key.clone(),
            size_bytes: bytes.len() as u64,
            checksum: ArtifactChecksum::new(Sha256::digest(bytes).into()),
            object_generation: object_generation_for_upload_id(upload.as_str()),
        };
        (upload, receipt)
    }
    async fn seal(
        store: &FilesystemArtifactStore,
        key: &ArtifactKey,
        bytes: &[u8],
    ) -> ArtifactWriteReceipt {
        let (upload, receipt) = stage(store, key, bytes).await;
        store
            .complete_quarantine_verified(&upload, &receipt)
            .await
            .expect("positive seal");
        receipt
    }
    fn object(root: &Path, key: &ArtifactKey, generation: ArtifactObjectGeneration) -> PathBuf {
        root.join(".quarantine")
            .join(key.tenant_id().to_string())
            .join(key.session_id().to_string())
            .join(key.artifact_id().to_string())
            .join(generation_name(generation))
    }

    #[tokio::test]
    async fn private_seal_is_exactly_verified_and_never_publicly_readable() {
        let (root, store, key) = fixture();
        let receipt = seal(&store, &key, b"found").await;
        let path = object(root.path(), &key, receipt.object_generation());
        assert_eq!(std::fs::read(path.join("data")).expect("payload"), b"found");
        for name in ["data", "key", "receipt", "lock"] {
            assert_eq!(
                std::fs::metadata(path.join(name))
                    .expect("private file")
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert_eq!(
            store
                .inspect_quarantine(&key.namespace(), &key, receipt.object_generation())
                .await
                .expect("inspect"),
            Some((receipt.clone(), false))
        );
        let content = ArtifactContentMetadata::new(
            5,
            *receipt.checksum(),
            "text/plain",
            crate::ArtifactContentSource::ClientUpload,
            "upload",
        )
        .expect("metadata");
        assert!(matches!(
            store
                .open_read(
                    &key.namespace(),
                    &key,
                    receipt.object_generation(),
                    &content,
                    ArtifactReadLimits::new(2).expect("limits")
                )
                .await,
            Err(ArtifactObjectError::NotAvailable)
        ));
        assert_eq!(
            store.quarantine_inventory(1).await.expect("inventory"),
            vec![(receipt, false)]
        );
    }

    #[tokio::test]
    async fn invalid_seal_keeps_multipart_until_positive_abort() {
        let (root, store, key) = fixture();
        let (upload, mut receipt) = stage(&store, &key, b"found").await;
        receipt.checksum = ArtifactChecksum::new([99; 32]);
        assert!(
            store
                .complete_quarantine_verified(&upload, &receipt)
                .await
                .expect_err("mismatch")
                .is_completion_uncertain()
        );
        assert!(
            root.path()
                .join(".multipart")
                .join(upload.as_str())
                .join("data")
                .exists()
        );
        assert!(!object(root.path(), &key, receipt.object_generation()).exists());
        store.abort(&upload).await.expect("positive abort");
        assert!(
            !root
                .path()
                .join(".multipart")
                .join(upload.as_str())
                .exists()
        );
    }

    #[tokio::test]
    async fn interrupted_delete_rechecks_tombstone_payload_before_retrying() {
        let (root, store, key) = fixture();
        let receipt = seal(&store, &key, b"found").await;
        let live = object(root.path(), &key, receipt.object_generation());
        let tombstone = live.with_file_name(deleted_name(receipt.object_generation()));
        std::fs::rename(&live, &tombstone).expect("crash after deletion rename");
        File::open(tombstone.parent().expect("parent"))
            .expect("parent fd")
            .sync_all()
            .expect("durable intent");
        std::fs::write(tombstone.join("data"), b"other").expect("replacement");
        assert_eq!(
            store
                .delete_quarantine_exact(&key.namespace(), &key, receipt.object_generation())
                .await,
            Err(ArtifactObjectError::IntegrityMismatch)
        );
        assert_eq!(
            std::fs::read(tombstone.join("data")).expect("replacement survives"),
            b"other"
        );
        std::fs::write(tombstone.join("data"), b"found").expect("restore exact owned bytes");
        assert_eq!(
            store
                .delete_quarantine_exact(&key.namespace(), &key, receipt.object_generation())
                .await
                .expect("positive retry"),
            ArtifactDeleteOutcome::AlreadyDeleted
        );
        assert!(!tombstone.join("data").exists());
        assert!(tombstone.join("receipt").exists());
    }

    #[tokio::test]
    async fn exact_delete_and_marker_prune_preserve_other_generation() {
        let (root, store, key) = fixture();
        let first = seal(&store, &key, b"first").await;
        let second = seal(&store, &key, b"other").await;
        assert_ne!(first.object_generation(), second.object_generation());
        assert_eq!(
            store
                .delete_quarantine_exact(&key.namespace(), &key, first.object_generation())
                .await
                .expect("delete first"),
            ArtifactDeleteOutcome::Deleted
        );
        assert_eq!(
            store
                .delete_quarantine_exact(&key.namespace(), &key, first.object_generation())
                .await
                .expect("lost reply retry"),
            ArtifactDeleteOutcome::AlreadyDeleted
        );
        store
            .prune_quarantine_delete_receipt(&key.namespace(), &key, first.object_generation())
            .await
            .expect("prune first");
        assert_eq!(
            std::fs::read(object(root.path(), &key, second.object_generation()).join("data"))
                .expect("other generation"),
            b"other"
        );
        assert_eq!(
            store
                .quarantine_inventory(2)
                .await
                .expect("surviving generation"),
            vec![(second, false)]
        );
    }

    #[tokio::test]
    async fn private_root_replacement_cannot_authorize_delete_or_inspection() {
        let (root, store, key) = fixture();
        let receipt = seal(&store, &key, b"found").await;
        std::fs::rename(
            root.path().join(".quarantine"),
            root.path().join("original-private"),
        )
        .expect("replace root");
        std::fs::create_dir(root.path().join(".quarantine")).expect("new root");
        std::fs::set_permissions(
            root.path().join(".quarantine"),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("mode");
        assert_eq!(
            store
                .inspect_quarantine(&key.namespace(), &key, receipt.object_generation())
                .await,
            Err(ArtifactObjectError::IntegrityMismatch)
        );
        assert_eq!(
            store
                .delete_quarantine_exact(&key.namespace(), &key, receipt.object_generation())
                .await,
            Err(ArtifactObjectError::IntegrityMismatch)
        );
        let saved = root
            .path()
            .join("original-private")
            .join(key.tenant_id().to_string())
            .join(key.session_id().to_string())
            .join(key.artifact_id().to_string())
            .join(generation_name(receipt.object_generation()))
            .join("data");
        assert_eq!(std::fs::read(saved).expect("original untouched"), b"found");
    }

    #[tokio::test]
    async fn private_payload_hardlinks_and_parent_symlinks_fail_closed() {
        let (root, store, key) = fixture();
        let receipt = seal(&store, &key, b"found").await;
        let live = object(root.path(), &key, receipt.object_generation());
        let alias = root.path().join("payload-alias");
        std::fs::hard_link(live.join("data"), &alias).expect("hardlink replacement");
        assert_eq!(
            store
                .delete_quarantine_exact(&key.namespace(), &key, receipt.object_generation())
                .await,
            Err(ArtifactObjectError::IntegrityMismatch)
        );
        std::fs::remove_file(alias).expect("remove alias");
        let parent = live.parent().expect("artifact parent");
        let moved = parent.with_file_name("saved-artifact");
        std::fs::rename(parent, &moved).expect("move parent");
        std::os::unix::fs::symlink(&moved, parent).expect("symlink parent");
        assert_eq!(
            store
                .delete_quarantine_exact(&key.namespace(), &key, receipt.object_generation())
                .await,
            Err(ArtifactObjectError::IntegrityMismatch)
        );
        assert_eq!(
            std::fs::read(
                moved
                    .join(generation_name(receipt.object_generation()))
                    .join("data")
            )
            .expect("payload survives"),
            b"found"
        );
    }

    #[tokio::test]
    async fn interrupted_receipt_prune_retries_and_removes_empty_private_namespace() {
        let (root, store, key) = fixture();
        let receipt = seal(&store, &key, b"found").await;
        store
            .delete_quarantine_exact(&key.namespace(), &key, receipt.object_generation())
            .await
            .expect("positive delete");
        let tombstone = object(root.path(), &key, receipt.object_generation())
            .with_file_name(deleted_name(receipt.object_generation()));
        std::fs::remove_file(tombstone.join("receipt")).expect("crash after receipt prune");
        std::fs::remove_file(tombstone.join("key")).expect("partial key prune");
        store
            .prune_quarantine_delete_receipt(&key.namespace(), &key, receipt.object_generation())
            .await
            .expect("durable-retirement retry");
        assert!(!tombstone.exists());
        assert!(
            std::fs::read_dir(root.path().join(".quarantine"))
                .expect("private namespace")
                .next()
                .is_none()
        );
        store
            .prune_quarantine_delete_receipt(&key.namespace(), &key, receipt.object_generation())
            .await
            .expect("lost prune reply retry");
    }

    #[tokio::test]
    async fn empty_private_directories_cannot_bypass_inventory_work_bound() {
        let (root, store, _key) = fixture();
        for _ in 0..81 {
            let path = root
                .path()
                .join(".quarantine")
                .join(TenantId::new().to_string());
            std::fs::create_dir(&path).expect("empty namespace");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("mode");
        }
        assert_eq!(
            store.quarantine_inventory(1).await,
            Err(ArtifactObjectError::IntegrityMismatch)
        );
    }
}
