//! Compile-time browser feature registry and resource boundaries.

#![forbid(unsafe_code)]

mod admission;
mod preflight;
mod registry;

pub use admission::{
    AdmissionClass, AdmissionError, AdmissionPermit, FeatureAdmission, FeatureConcurrencyLimits,
};
pub use preflight::{
    BoundedByteStream, ByteBudgetError, PdfLimits, PdfRequest, PreflightError, PreflightReceipt,
    ScrapeBudget, ScrapeLimits, ScrapeUsage, ScreenshotLimits, ScreenshotRequest,
};
pub use registry::{
    BuiltinFeature, FeatureFailurePolicy, FeatureManifest, FeatureProfile, FeatureRegistry,
    FeatureResourceRequest, InternalCapability, RegistryError,
};
