use serde::{Deserialize, Deserializer, Serialize};

use crate::{ChromiumBinaryDigest, SandboxError};

/// Immutable process defaults inherited by every Chromium renderer.
///
/// Resource digests identify entries in a separately verified runtime catalog;
/// they never authorize caller-provided environment variables or host paths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "schema", deny_unknown_fields)]
pub enum ChromiumProcessProfile {
    #[serde(rename = "baseline_v1")]
    BaselineV1,
    #[serde(rename = "native_locale_v1")]
    NativeLocaleV1 {
        locale: String,
        time_zone: String,
        catalog_digest: ChromiumBinaryDigest,
        locale_pak_digest: ChromiumBinaryDigest,
        icu_data_digest: ChromiumBinaryDigest,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_agent: Option<String>,
    },
}

impl<'de> Deserialize<'de> for ChromiumProcessProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Serde's internally tagged unit variant ignores remaining fields even
        // with deny_unknown_fields. An empty struct keeps BaselineV1 strict while
        // preserving the public unit-variant API.
        #[derive(Deserialize)]
        #[serde(tag = "schema", deny_unknown_fields)]
        enum WireProfile {
            #[serde(rename = "baseline_v1")]
            BaselineV1 {},
            #[serde(rename = "native_locale_v1")]
            NativeLocaleV1 {
                locale: String,
                time_zone: String,
                catalog_digest: ChromiumBinaryDigest,
                locale_pak_digest: ChromiumBinaryDigest,
                icu_data_digest: ChromiumBinaryDigest,
                #[serde(default)]
                user_agent: Option<String>,
            },
        }
        Ok(match WireProfile::deserialize(deserializer)? {
            WireProfile::BaselineV1 {} => Self::BaselineV1,
            WireProfile::NativeLocaleV1 {
                locale,
                time_zone,
                catalog_digest,
                locale_pak_digest,
                icu_data_digest,
                user_agent,
            } => Self::NativeLocaleV1 {
                locale,
                time_zone,
                catalog_digest,
                locale_pak_digest,
                icu_data_digest,
                user_agent,
            },
        })
    }
}

impl ChromiumProcessProfile {
    pub fn native_locale(
        locale: impl Into<String>,
        time_zone: impl Into<String>,
        catalog_digest: ChromiumBinaryDigest,
        locale_pak_digest: ChromiumBinaryDigest,
        icu_data_digest: ChromiumBinaryDigest,
    ) -> Result<Self, SandboxError> {
        let profile = Self::NativeLocaleV1 {
            locale: locale.into(),
            time_zone: time_zone.into(),
            catalog_digest,
            locale_pak_digest,
            icu_data_digest,
            user_agent: None,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Binds a custom UA to every renderer and worker from process startup.
    pub fn with_user_agent(mut self, user_agent: Option<String>) -> Result<Self, SandboxError> {
        let Self::NativeLocaleV1 {
            user_agent: current,
            ..
        } = &mut self
        else {
            return Err(SandboxError::InvalidChromiumProcessProfile);
        };
        *current = user_agent;
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub fn user_agent(&self) -> Option<&str> {
        match self {
            Self::BaselineV1 => None,
            Self::NativeLocaleV1 { user_agent, .. } => user_agent.as_deref(),
        }
    }

    /// Checks syntax and initialized resource identities. The runtime catalog
    /// separately verifies supported locale/timezone pairs and resource bytes.
    pub fn validate(&self) -> Result<(), SandboxError> {
        let Self::NativeLocaleV1 {
            locale,
            time_zone,
            catalog_digest,
            locale_pak_digest,
            icu_data_digest,
            user_agent,
        } = self
        else {
            return Ok(());
        };
        let locale_is_valid = locale.len() <= 64
            && locale
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            && locale.split('-').all(|segment| {
                (1..=16).contains(&segment.len())
                    && segment.bytes().all(|byte| byte.is_ascii_alphanumeric())
            });
        let time_zone_is_valid = !time_zone.is_empty()
            && time_zone.len() <= 128
            && time_zone.split('/').all(|component| {
                !component.is_empty()
                    && component.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-')
                    })
            });
        let digests_are_initialized = [catalog_digest, locale_pak_digest, icu_data_digest]
            .into_iter()
            .all(|digest| digest.as_bytes().iter().any(|byte| *byte != 0));
        let user_agent_is_valid = user_agent.as_ref().is_none_or(|value| {
            !value.trim().is_empty() && value.len() <= 4_096 && !value.chars().any(char::is_control)
        });
        if !locale_is_valid
            || !time_zone_is_valid
            || !digests_are_initialized
            || !user_agent_is_valid
        {
            return Err(SandboxError::InvalidChromiumProcessProfile);
        }
        Ok(())
    }

    #[must_use]
    pub fn locale(&self) -> Option<&str> {
        match self {
            Self::BaselineV1 => None,
            Self::NativeLocaleV1 { locale, .. } => Some(locale),
        }
    }

    #[must_use]
    pub fn timezone(&self) -> Option<&str> {
        match self {
            Self::BaselineV1 => None,
            Self::NativeLocaleV1 { time_zone, .. } => Some(time_zone),
        }
    }
}
