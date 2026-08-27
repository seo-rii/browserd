use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::{Uuid, Version};

#[derive(Clone, Debug)]
pub struct IdParseError {
    kind: &'static str,
    expected_version: Version,
}

impl IdParseError {
    const fn new(kind: &'static str, expected_version: Version) -> Self {
        Self {
            kind,
            expected_version,
        }
    }
}

impl fmt::Display for IdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {}: expected UUID version {:?}",
            self.kind, self.expected_version
        )
    }
}

impl std::error::Error for IdParseError {}

fn validate_uuid_version(
    uuid: Uuid,
    kind: &'static str,
    expected_version: Version,
) -> Result<Uuid, IdParseError> {
    if uuid.get_version() == Some(expected_version) {
        Ok(uuid)
    } else {
        Err(IdParseError::new(kind, expected_version))
    }
}

macro_rules! uuid_id {
    ($name:ident, $kind:literal, $version:path, $constructor:expr) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self($constructor)
            }

            pub fn from_uuid(uuid: Uuid) -> Result<Self, IdParseError> {
                validate_uuid_version(uuid, $kind, $version).map(Self)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value)
                    .map_err(|_| IdParseError::new($kind, $version))
                    .and_then(Self::from_uuid)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let uuid = Uuid::deserialize(deserializer)?;
                Self::from_uuid(uuid).map_err(<D::Error as serde::de::Error>::custom)
            }
        }
    };
}

uuid_id!(TenantId, "tenant ID", Version::SortRand, Uuid::now_v7());
uuid_id!(
    PrincipalId,
    "principal ID",
    Version::SortRand,
    Uuid::now_v7()
);
uuid_id!(
    OperationId,
    "operation ID",
    Version::SortRand,
    Uuid::now_v7()
);
uuid_id!(SessionId, "session ID", Version::SortRand, Uuid::now_v7());
uuid_id!(ShardId, "shard ID", Version::SortRand, Uuid::now_v7());
uuid_id!(ActionId, "action ID", Version::SortRand, Uuid::now_v7());
uuid_id!(ApprovalId, "approval ID", Version::SortRand, Uuid::now_v7());
uuid_id!(ArtifactId, "artifact ID", Version::SortRand, Uuid::now_v7());

uuid_id!(PageId, "page ID", Version::Random, Uuid::new_v4());
uuid_id!(SnapshotId, "snapshot ID", Version::Random, Uuid::new_v4());
uuid_id!(LeaseId, "lease ID", Version::Random, Uuid::new_v4());

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidWorkerId;

impl fmt::Display for InvalidWorkerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("worker ID must be a non-empty stable deployment identity")
    }
}

impl std::error::Error for InvalidWorkerId {}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkerId(String);

impl WorkerId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidWorkerId> {
        let value = value.into();
        if value.is_empty()
            || value.trim() != value
            || value.len() > 255
            || value.chars().any(char::is_control)
        {
            return Err(InvalidWorkerId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for WorkerId {
    type Err = InvalidWorkerId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for WorkerId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WorkerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(<D::Error as serde::de::Error>::custom)
    }
}
