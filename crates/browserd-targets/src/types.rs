#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetKind {
    Page,
    Iframe,
    DedicatedWorker,
    SharedWorker,
    ServiceWorker,
    Prerender,
    Extension,
    Devtools,
    Unknown(String),
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct TargetTime(u64);

impl TargetTime {
    #[must_use]
    pub const fn new(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    pub(crate) const fn milliseconds(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TargetIncarnation(u64);

impl TargetIncarnation {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionIncarnation(u64);

impl SessionIncarnation {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DocumentEpoch(u64);

impl DocumentEpoch {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) fn checked_next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

/// An arbitrary-precision monotonic revision. Its vector is little-endian so
/// incrementing never wraps, even after the low word is exhausted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UrlRevision(pub(crate) Vec<u64>);

impl UrlRevision {
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(vec![value])
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FrameId(String);

impl FrameId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}
