#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use browserd_chromium::{
    ArtifactFile, ChromiumArtifactIdentity, CompatibilityArtifact, CompatibilityError,
    NativeLocaleResource, NativeProfileCatalogV1, NativeProfileError, Sha256Digest,
    VerifiedNativeProfileCatalog,
};
use browserd_sandbox::ChromiumProcessProfile;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

const CATALOG: &str = "native-process-profiles.json";

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_hex(&hex::encode(Sha256::digest(bytes))).expect("valid test digest")
}

fn write(root: &Path, relative: &Path, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("artifact parent")).expect("create artifact directory");
    fs::write(path, bytes).expect("write artifact file");
}

struct Fixture {
    root: TempDir,
    artifact: CompatibilityArtifact,
}

impl Fixture {
    fn with_catalog_value(value: serde_json::Value) -> Self {
        let root = tempdir().expect("test artifact directory");
        let binary = digest(b"pinned chromium");
        let catalog = serde_json::to_vec(&value).expect("serialize catalog");
        for (relative, bytes) in [
            ("bin/chrome", b"pinned chromium".as_slice()),
            ("bin/icudtl.dat", b"pinned ICU".as_slice()),
            (
                "resource-packs/ko.pak",
                b"pinned Korean resource pack".as_slice(),
            ),
            (CATALOG, catalog.as_slice()),
        ] {
            write(root.path(), Path::new(relative), bytes);
        }
        let artifact = CompatibilityArtifact {
            identity: ChromiumArtifactIdentity {
                binary_digest: binary,
                product_version: "153.0.8010.12".to_owned(),
                chromium_revision: "971a7443b0c9b0a9b2860529b33331b76077ec62".to_owned(),
                browser_protocol_schema_digest: digest(b"browser protocol"),
                js_protocol_schema_digest: digest(b"js protocol"),
                launch_profile_digest: digest(&catalog),
                extension_bundle_digest: digest(b"extensions"),
                font_bundle_digest: digest(b"fonts"),
                certificate_runtime_bundle_digest: digest(b"certificates"),
            },
            files: vec![
                ArtifactFile::new("bin/chrome", binary),
                ArtifactFile::new("bin/icudtl.dat", digest(b"pinned ICU")),
                ArtifactFile::new(
                    "resource-packs/ko.pak",
                    digest(b"pinned Korean resource pack"),
                ),
                ArtifactFile::new(CATALOG, digest(&catalog)),
            ],
        };
        Self { root, artifact }
    }

    fn new() -> Self {
        Self::with_catalog_value(json!({
            "schema_version": 1,
            "icu_data": "bin/icudtl.dat",
            "locales": [{"locale": "ko-KR", "pak": "resource-packs/ko.pak"}],
            "time_zones": ["Asia/Seoul", "UTC"]
        }))
    }

    fn load(&self) -> Result<VerifiedNativeProfileCatalog, NativeProfileError> {
        VerifiedNativeProfileCatalog::load(self.root.path(), &self.artifact)
    }
}

#[test]
fn verifies_catalog_identity_and_selects_exact_native_profile_resources() {
    let fixture = Fixture::new();
    let catalog = fixture.load().expect("valid verified catalog");
    assert_eq!(
        catalog.catalog_digest(),
        fixture.artifact.identity.launch_profile_digest
    );
    assert_eq!(
        catalog.binary_digest(),
        fixture.artifact.identity.binary_digest
    );
    assert_eq!(
        catalog.icu_data(),
        (
            fixture.root.path().join("bin/icudtl.dat").as_path(),
            digest(b"pinned ICU")
        )
    );
    assert_eq!(
        catalog.time_zones(),
        &["Asia/Seoul".to_owned(), "UTC".to_owned()]
    );
    assert_eq!(catalog.locale_resources().len(), 1);
    let resource = &catalog.locale_resources()[0];
    assert_eq!(resource.locale, "ko-KR");
    assert_eq!(
        resource.source,
        fixture.root.path().join("resource-packs/ko.pak")
    );
    assert_eq!(resource.digest, digest(b"pinned Korean resource pack"));
    assert_eq!(
        catalog
            .process_profile("ko-KR", "Asia/Seoul")
            .expect("listed exact profile"),
        ChromiumProcessProfile::native_locale(
            "ko-KR",
            "Asia/Seoul",
            fixture.artifact.identity.launch_profile_digest.into(),
            digest(b"pinned Korean resource pack").into(),
            digest(b"pinned ICU").into(),
        )
        .expect("valid process profile")
    );
}

#[test]
fn catalog_json_has_the_declared_strict_versioned_shape() {
    let catalog = NativeProfileCatalogV1 {
        schema_version: 1,
        icu_data: PathBuf::from("icudtl.dat"),
        locales: vec![NativeLocaleResource {
            locale: "ko-KR".to_owned(),
            pak: PathBuf::from("locales/ko.pak"),
        }],
        time_zones: vec!["Asia/Seoul".to_owned()],
    };
    let value = serde_json::to_value(&catalog).expect("serialize shape");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(
        serde_json::from_value::<NativeProfileCatalogV1>(value).expect("deserialize shape"),
        catalog
    );
}

#[test]
fn requires_the_named_catalog_and_its_exact_launch_profile_digest() {
    let mut fixture = Fixture::new();
    fixture.artifact.identity.launch_profile_digest = digest(b"different launch profile");
    assert_eq!(
        fixture.load().expect_err("wrong catalog identity"),
        NativeProfileError::CatalogDigestMismatch
    );

    let mut fixture = Fixture::new();
    let catalog_file = fixture
        .artifact
        .files
        .iter_mut()
        .find(|file| file.relative_path == Path::new(CATALOG))
        .expect("catalog file");
    catalog_file.relative_path = PathBuf::from("other-profile.json");
    fs::rename(
        fixture.root.path().join(CATALOG),
        fixture.root.path().join("other-profile.json"),
    )
    .expect("rename catalog");
    assert_eq!(
        fixture.load().expect_err("catalog filename differs"),
        NativeProfileError::CatalogNotInManifest
    );
}

#[test]
fn rejects_resources_that_are_not_listed_in_the_verified_manifest() {
    for excluded in ["bin/icudtl.dat", "resource-packs/ko.pak"] {
        let mut fixture = Fixture::new();
        fixture
            .artifact
            .files
            .retain(|file| file.relative_path != Path::new(excluded));
        assert_eq!(
            fixture.load().expect_err("unlisted resource"),
            NativeProfileError::ResourceNotInManifest,
            "resource {excluded}"
        );
    }
}

#[test]
fn rejects_changed_catalog_binary_icu_and_locale_resource_bytes() {
    for changed in [
        CATALOG,
        "bin/chrome",
        "bin/icudtl.dat",
        "resource-packs/ko.pak",
    ] {
        let fixture = Fixture::new();
        write(
            fixture.root.path(),
            Path::new(changed),
            b"unapproved replacement",
        );
        assert_eq!(
            fixture.load().expect_err("changed resource"),
            NativeProfileError::Compatibility(CompatibilityError::DigestMismatch {
                relative_path: changed.to_owned()
            })
        );
    }
}

#[test]
fn rejects_unsafe_locale_and_timezone_aliases() {
    for invalid in [
        "",
        "-ko",
        "ko-",
        "ko--KR",
        "../ko",
        "ko_KR",
        "ko KR",
        "한국어",
        "0ko-KR",
        "ko-abcdefghijklmnopq",
    ] {
        let fixture = Fixture::with_catalog_value(json!({
            "schema_version": 1, "icu_data": "bin/icudtl.dat",
            "locales": [{"locale": invalid, "pak": "resource-packs/ko.pak"}],
            "time_zones": ["Asia/Seoul"]
        }));
        assert_eq!(
            fixture.load().expect_err("unsafe locale"),
            NativeProfileError::InvalidLocale,
            "locale {invalid:?}"
        );
    }
    for invalid in [
        "",
        "/Asia/Seoul",
        "Asia/",
        "Asia//Seoul",
        "Asia/../Seoul",
        "Asia.Seoul",
        "Asia Seoul",
        "서울",
    ] {
        let fixture = Fixture::with_catalog_value(json!({
            "schema_version": 1, "icu_data": "bin/icudtl.dat",
            "locales": [{"locale": "ko-KR", "pak": "resource-packs/ko.pak"}],
            "time_zones": [invalid]
        }));
        assert_eq!(
            fixture.load().expect_err("unsafe timezone"),
            NativeProfileError::InvalidTimeZone,
            "timezone {invalid:?}"
        );
    }
    for (locale, timezone, expected) in [
        (
            "a".repeat(65),
            "UTC".to_owned(),
            NativeProfileError::InvalidLocale,
        ),
        (
            "ko-KR".to_owned(),
            "a".repeat(129),
            NativeProfileError::InvalidTimeZone,
        ),
    ] {
        let fixture = Fixture::with_catalog_value(json!({
            "schema_version": 1, "icu_data": "bin/icudtl.dat",
            "locales": [{"locale": locale, "pak": "resource-packs/ko.pak"}],
            "time_zones": [timezone]
        }));
        assert_eq!(fixture.load().expect_err("oversized alias"), expected);
    }
}

#[test]
fn native_profile_selection_never_falls_back_from_an_unlisted_exact_tag_or_timezone() {
    let fixture = Fixture::new();
    let catalog = fixture.load().expect("verified catalog");
    for (locale, timezone, expected) in [
        ("ko", "Asia/Seoul", NativeProfileError::UnsupportedLocale),
        ("ko-kr", "Asia/Seoul", NativeProfileError::UnsupportedLocale),
        (
            "ko-KR",
            "Asia/Tokyo",
            NativeProfileError::UnsupportedTimeZone,
        ),
    ] {
        assert_eq!(
            catalog
                .process_profile(locale, timezone)
                .expect_err("unsupported exact profile"),
            expected,
            "unsupported {locale}/{timezone}"
        );
    }
}

#[test]
fn rejects_duplicate_manifest_paths_locale_aliases_timezone_names_and_binary_mapping() {
    let mut fixture = Fixture::new();
    fixture
        .artifact
        .files
        .push(fixture.artifact.files[3].clone());
    assert_eq!(
        fixture.load().expect_err("duplicate catalog file"),
        NativeProfileError::DuplicateManifestPath
    );

    let mut fixture = Fixture::new();
    write(
        fixture.root.path(),
        Path::new("other/chrome"),
        b"pinned chromium",
    );
    fixture.artifact.files.push(ArtifactFile::new(
        "other/chrome",
        fixture.artifact.identity.binary_digest,
    ));
    assert_eq!(
        fixture.load().expect_err("ambiguous binary file"),
        NativeProfileError::BinaryMappingInvalid
    );

    for (locales, time_zones, expected) in [
        (
            json!([{ "locale": "ko-KR", "pak": "resource-packs/ko.pak" }, {"locale": "ko-KR", "pak": "resource-packs/ko.pak"}]),
            json!(["UTC"]),
            NativeProfileError::DuplicateLocale,
        ),
        (
            json!([{ "locale": "ko-KR", "pak": "resource-packs/ko.pak" }]),
            json!(["UTC", "UTC"]),
            NativeProfileError::DuplicateTimeZone,
        ),
    ] {
        let fixture = Fixture::with_catalog_value(json!({
            "schema_version": 1, "icu_data": "bin/icudtl.dat", "locales": locales, "time_zones": time_zones
        }));
        assert_eq!(
            fixture.load().expect_err("duplicate allowlist alias"),
            expected
        );
    }
}

#[test]
fn rejects_unlisted_icu_location_unknown_fields_and_unsupported_schema_versions() {
    for (value, expected) in [
        (
            json!({"schema_version": 2, "icu_data": "bin/icudtl.dat", "locales": [{"locale":"ko-KR","pak":"resource-packs/ko.pak"}], "time_zones":["UTC"]}),
            NativeProfileError::UnsupportedSchema,
        ),
        (
            json!({"schema_version": 1, "icu_data": "bin/icudtl.dat", "locales": [{"locale":"ko-KR","pak":"resource-packs/ko.pak"}], "time_zones":["UTC"], "unchecked": true}),
            NativeProfileError::InvalidCatalog,
        ),
        (
            json!({"schema_version": 1, "icu_data": "bin/icudtl.dat", "locales": [{"locale":"ko-KR","pak":"resource-packs/ko.pak", "unchecked": true}], "time_zones":["UTC"]}),
            NativeProfileError::InvalidCatalog,
        ),
    ] {
        assert_eq!(
            Fixture::with_catalog_value(value)
                .load()
                .expect_err("invalid catalog shape"),
            expected
        );
    }
    let mut fixture = Fixture::with_catalog_value(json!({
        "schema_version": 1, "icu_data": "other/icudtl.dat",
        "locales": [{"locale":"ko-KR","pak":"resource-packs/ko.pak"}], "time_zones":["UTC"]
    }));
    write(
        fixture.root.path(),
        Path::new("other/icudtl.dat"),
        b"pinned ICU",
    );
    fixture
        .artifact
        .files
        .push(ArtifactFile::new("other/icudtl.dat", digest(b"pinned ICU")));
    assert_eq!(
        fixture
            .load()
            .expect_err("ICU must be beside approved executable"),
        NativeProfileError::InvalidIcuLocation
    );
}

#[test]
fn rejects_empty_allowlists_zero_digests_and_a_catalog_larger_than_one_mib() {
    for (locales, time_zones) in [
        (json!([]), json!(["UTC"])),
        (
            json!([{"locale":"ko-KR","pak":"resource-packs/ko.pak"}]),
            json!([]),
        ),
    ] {
        let fixture = Fixture::with_catalog_value(json!({
            "schema_version": 1, "icu_data": "bin/icudtl.dat", "locales": locales, "time_zones": time_zones
        }));
        assert_eq!(
            fixture.load().expect_err("empty allowlist"),
            NativeProfileError::EmptyAllowlist
        );
    }
    let mut fixture = Fixture::new();
    fixture.artifact.files[2].digest =
        Sha256Digest::from_hex(&"0".repeat(64)).expect("zero digest");
    assert_eq!(
        fixture.load().expect_err("zero resource digest"),
        NativeProfileError::ZeroDigest
    );

    let mut fixture = Fixture::new();
    let too_large = vec![b' '; 1024 * 1024 + 1];
    write(fixture.root.path(), Path::new(CATALOG), &too_large);
    fixture.artifact.identity.launch_profile_digest = digest(&too_large);
    fixture.artifact.files[3].digest = digest(&too_large);
    write(
        fixture.root.path(),
        Path::new("bin/chrome"),
        b"unverified binary",
    );
    assert_eq!(
        fixture.load().expect_err("oversized catalog"),
        NativeProfileError::CatalogTooLarge
    );
}

#[test]
fn catalog_allowlists_fit_the_sandbox_resource_contract_bounds() {
    for (locales, time_zones) in [
        (
            (0..257)
                .map(|index| json!({"locale":format!("ko-X{index}"),"pak":"resource-packs/ko.pak"}))
                .collect::<Vec<_>>(),
            vec!["UTC".to_owned()],
        ),
        (
            vec![json!({"locale":"ko-KR","pak":"resource-packs/ko.pak"})],
            (0..1025)
                .map(|index| format!("Etc/Test{index}"))
                .collect::<Vec<_>>(),
        ),
    ] {
        let fixture = Fixture::with_catalog_value(json!({
            "schema_version":1, "icu_data":"bin/icudtl.dat", "locales":locales, "time_zones":time_zones
        }));
        assert_eq!(
            fixture
                .load()
                .expect_err("resource allowlist exceeds sandbox bound"),
            NativeProfileError::AllowlistTooLarge
        );
    }
}
