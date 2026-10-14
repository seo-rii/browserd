//! Compile-time browser feature registry and resource boundaries.

#![forbid(unsafe_code)]

mod admission;
mod capture;
pub use capture::{
    CAPTURE_CHUNK_BYTES, CaptureCommand, CaptureDelivery, MAX_CAPTURE_BYTES,
    MAX_INLINE_CAPTURE_BYTES, MAX_SCREENSHOT_BYTES, PdfOptions, ScrapeOptions, ScreenshotClip,
    ScreenshotFormat, ScreenshotOptions,
};
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
