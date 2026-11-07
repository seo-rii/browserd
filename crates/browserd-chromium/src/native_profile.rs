//! Artifact-bound native locale and timezone profiles for dedicated Chromium processes.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use browserd_sandbox::ChromiumProcessProfile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{CompatibilityArtifact, CompatibilityError, Sha256Digest};

const CATALOG_PATH: &str = "native-process-profiles.json";
const MAX_CATALOG_BYTES: usize = 1024 * 1024;
const MAX_LOCALES: usize = 256;
const MAX_TIME_ZONES: usize = 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLocaleResource {
    pub locale: String,
    pub pak: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeProfileCatalogV1 {
    pub schema_version: u32,
    pub icu_data: PathBuf,
    pub locales: Vec<NativeLocaleResource>,
    pub time_zones: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedNativeLocaleResource {
    pub locale: String,
    pub source: PathBuf,
    pub digest: Sha256Digest,
}

#[derive(Clone, Debug)]
pub struct VerifiedNativeProfileCatalog {
    catalog_digest: Sha256Digest,
    binary_digest: Sha256Digest,
    icu_data: (PathBuf, Sha256Digest),
    locale_resources: Vec<VerifiedNativeLocaleResource>,
    time_zones: Vec<String>,
}

impl VerifiedNativeProfileCatalog {
    pub fn load(root: &Path, artifact: &CompatibilityArtifact) -> Result<Self, NativeProfileError> {
        let mut files = BTreeMap::new();
        for file in &artifact.files {
            if file.digest == Sha256Digest([0; 32]) {
                return Err(NativeProfileError::ZeroDigest);
            }
            if files
                .insert(file.relative_path.clone(), file.digest)
                .is_some()
            {
                return Err(NativeProfileError::DuplicateManifestPath);
            }
        }
        if artifact.identity.binary_digest == Sha256Digest([0; 32])
            || artifact.identity.launch_profile_digest == Sha256Digest([0; 32])
        {
            return Err(NativeProfileError::ZeroDigest);
        }
        let catalog_digest = files
            .get(Path::new(CATALOG_PATH))
            .copied()
            .ok_or(NativeProfileError::CatalogNotInManifest)?;
        if catalog_digest != artifact.identity.launch_profile_digest {
            return Err(NativeProfileError::CatalogDigestMismatch);
        }

        let mut binaries = artifact
            .files
            .iter()
            .filter(|file| file.digest == artifact.identity.binary_digest);
        let binary = binaries
            .next()
            .ok_or(NativeProfileError::BinaryMappingInvalid)?;
        if binaries.next().is_some() {
            return Err(NativeProfileError::BinaryMappingInvalid);
        }
        let expected_icu = binary
            .relative_path
            .parent()
            .ok_or(NativeProfileError::BinaryMappingInvalid)?
            .join("icudtl.dat");

        let catalog_path = root.join(CATALOG_PATH);
        let metadata = catalog_path
            .symlink_metadata()
            .map_err(|_| NativeProfileError::CatalogReadFailed)?;
        if metadata.len() > MAX_CATALOG_BYTES as u64 {
            return Err(NativeProfileError::CatalogTooLarge);
        }

        // Verify every manifest file, including catalog paths and symlink policy,
        // before opening resources referenced by the catalog.
        artifact.verify(root)?;
        let file = File::open(catalog_path).map_err(|_| NativeProfileError::CatalogReadFailed)?;
        let mut bytes = Vec::new();
        file.take((MAX_CATALOG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| NativeProfileError::CatalogReadFailed)?;
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err(NativeProfileError::CatalogTooLarge);
        }
        // Parse exactly the bounded bytes whose digest was checked. A catalog
        // replacement between manifest verification and this read fails closed.
        if Sha256Digest(Sha256::digest(&bytes).into()) != catalog_digest {
            return Err(NativeProfileError::CatalogDigestMismatch);
        }
        let catalog: NativeProfileCatalogV1 =
            serde_json::from_slice(&bytes).map_err(|_| NativeProfileError::InvalidCatalog)?;
        if catalog.schema_version != 1 {
            return Err(NativeProfileError::UnsupportedSchema);
        }
        if catalog.icu_data != expected_icu {
            return Err(NativeProfileError::InvalidIcuLocation);
        }
        if catalog.locales.is_empty() || catalog.time_zones.is_empty() {
            return Err(NativeProfileError::EmptyAllowlist);
        }
        if catalog.locales.len() > MAX_LOCALES || catalog.time_zones.len() > MAX_TIME_ZONES {
            return Err(NativeProfileError::AllowlistTooLarge);
        }
        let icu_data = verified_resource(root, &files, &catalog.icu_data)?;
        let mut locale_names = BTreeSet::new();
        let mut locale_resources = Vec::with_capacity(catalog.locales.len());
        for resource in catalog.locales {
            if resource.locale.len() > 64
                || !resource
                    .locale
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphabetic)
                || !resource.locale.split('-').all(|segment| {
                    (1..=16).contains(&segment.len())
                        && segment.bytes().all(|byte| byte.is_ascii_alphanumeric())
                })
            {
                return Err(NativeProfileError::InvalidLocale);
            }
            if !locale_names.insert(resource.locale.clone()) {
                return Err(NativeProfileError::DuplicateLocale);
            }
            let (source, digest) = verified_resource(root, &files, &resource.pak)?;
            locale_resources.push(VerifiedNativeLocaleResource {
                locale: resource.locale,
                source,
                digest,
            });
        }
        let mut timezone_names = BTreeSet::new();
        for timezone in &catalog.time_zones {
            if timezone.is_empty()
                || timezone.len() > 128
                || !timezone.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-' | b'/')
                })
                || timezone.split('/').any(str::is_empty)
            {
                return Err(NativeProfileError::InvalidTimeZone);
            }
            if !timezone_names.insert(timezone.clone()) {
                return Err(NativeProfileError::DuplicateTimeZone);
            }
        }
        Ok(Self {
            catalog_digest,
            binary_digest: artifact.identity.binary_digest,
            icu_data,
            locale_resources,
            time_zones: catalog.time_zones,
        })
    }

    pub const fn catalog_digest(&self) -> Sha256Digest {
        self.catalog_digest
    }

    pub const fn binary_digest(&self) -> Sha256Digest {
        self.binary_digest
    }

    pub fn icu_data(&self) -> (&Path, Sha256Digest) {
        (self.icu_data.0.as_path(), self.icu_data.1)
    }

    pub fn locale_resources(&self) -> &[VerifiedNativeLocaleResource] {
        &self.locale_resources
    }

    pub fn time_zones(&self) -> &[String] {
        &self.time_zones
    }

    pub fn process_profile(
        &self,
        locale: &str,
        time_zone: &str,
    ) -> Result<ChromiumProcessProfile, NativeProfileError> {
        let resource = self
            .locale_resources
            .iter()
            .find(|resource| resource.locale == locale)
            .ok_or(NativeProfileError::UnsupportedLocale)?;
        if !self.time_zones.iter().any(|allowed| allowed == time_zone) {
            return Err(NativeProfileError::UnsupportedTimeZone);
        }
        ChromiumProcessProfile::native_locale(
            locale,
            time_zone,
            self.catalog_digest.into(),
            resource.digest.into(),
            self.icu_data.1.into(),
        )
        .map_err(|_| NativeProfileError::InvalidProcessProfile)
    }
}

fn verified_resource(
    root: &Path,
    files: &BTreeMap<PathBuf, Sha256Digest>,
    relative: &Path,
) -> Result<(PathBuf, Sha256Digest), NativeProfileError> {
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(NativeProfileError::InvalidResourcePath);
    }
    let digest = files
        .get(relative)
        .copied()
        .ok_or(NativeProfileError::ResourceNotInManifest)?;
    Ok((root.join(relative), digest))
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NativeProfileError {
    #[error(transparent)]
    Compatibility(#[from] CompatibilityError),
    #[error("native-process-profiles.json must be listed in the artifact manifest")]
    CatalogNotInManifest,
    #[error("native profile catalog digest does not match the launch profile identity")]
    CatalogDigestMismatch,
    #[error("native profile catalog could not be read")]
    CatalogReadFailed,
    #[error("native profile catalog exceeds one MiB")]
    CatalogTooLarge,
    #[error("native profile catalog JSON is invalid")]
    InvalidCatalog,
    #[error("native profile catalog schema version must be one")]
    UnsupportedSchema,
    #[error("native profile artifact contains a zero digest")]
    ZeroDigest,
    #[error("native profile artifact contains a duplicate manifest path")]
    DuplicateManifestPath,
    #[error("native profile artifact must map the binary digest to exactly one file")]
    BinaryMappingInvalid,
    #[error("native profile ICU data must be icudtl.dat beside the verified binary")]
    InvalidIcuLocation,
    #[error("native profile locale and timezone allowlists must be nonempty")]
    EmptyAllowlist,
    #[error("native profile catalog allows at most 256 locales and 1024 timezones")]
    AllowlistTooLarge,
    #[error("native profile resource path is unsafe")]
    InvalidResourcePath,
    #[error("native profile resource is not listed in the verified manifest")]
    ResourceNotInManifest,
    #[error("native profile locale alias is unsafe")]
    InvalidLocale,
    #[error("native profile locale aliases must be unique")]
    DuplicateLocale,
    #[error("native profile timezone alias is unsafe")]
    InvalidTimeZone,
    #[error("native profile timezone names must be unique")]
    DuplicateTimeZone,
    #[error("requested exact locale is not in the native profile catalog")]
    UnsupportedLocale,
    #[error("requested exact timezone is not in the native profile catalog")]
    UnsupportedTimeZone,
    #[error("native process profile fields are invalid")]
    InvalidProcessProfile,
}
