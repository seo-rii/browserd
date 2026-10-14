use serde::{Deserialize, Serialize};

pub const MAX_CAPTURE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SCREENSHOT_BYTES: u64 = 8 * 1024 * 1024;
pub const CAPTURE_CHUNK_BYTES: usize = 64 * 1024;
/// Leaves room for base64 and metadata inside the durable action's 64 KiB result envelope.
pub const MAX_INLINE_CAPTURE_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureDelivery {
    Inline,
    #[default]
    Artifact,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenshotFormat {
    #[default]
    Png,
    Jpeg,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenshotClip {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScreenshotOptions {
    pub format: ScreenshotFormat,
    pub quality: Option<u8>,
    pub full_page: bool,
    pub clip: Option<ScreenshotClip>,
    pub omit_background: bool,
    pub delivery: CaptureDelivery,
}

impl ScreenshotOptions {
    #[must_use]
    pub fn validate(&self) -> bool {
        self.quality
            .is_none_or(|quality| quality <= 100 && self.format == ScreenshotFormat::Jpeg)
            && !(self.omit_background && self.format == ScreenshotFormat::Jpeg)
            && self.clip.is_none_or(|clip| {
                !self.full_page
                    && clip.width > 0
                    && clip.height > 0
                    && clip.width <= 4096
                    && clip.height <= 16384
                    && clip.x.checked_add(clip.width).is_some()
                    && clip.y.checked_add(clip.height).is_some()
            })
    }
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        match self.format {
            ScreenshotFormat::Png => "image/png",
            ScreenshotFormat::Jpeg => "image/jpeg",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PdfOptions {
    pub width_microns: u32,
    pub height_microns: u32,
    pub margin_top_microns: u32,
    pub margin_bottom_microns: u32,
    pub margin_left_microns: u32,
    pub margin_right_microns: u32,
    pub landscape: bool,
    pub print_background: bool,
    pub scale_milli: u32,
    pub page_ranges: String,
}
impl Default for PdfOptions {
    fn default() -> Self {
        Self {
            width_microns: 210_000,
            height_microns: 297_000,
            margin_top_microns: 10_000,
            margin_bottom_microns: 10_000,
            margin_left_microns: 10_000,
            margin_right_microns: 10_000,
            landscape: false,
            print_background: false,
            scale_milli: 1000,
            page_ranges: String::new(),
        }
    }
}
impl PdfOptions {
    #[must_use]
    pub fn validate(&self) -> bool {
        (10_000..=1_000_000).contains(&self.width_microns)
            && (10_000..=1_000_000).contains(&self.height_microns)
            && (100..=2000).contains(&self.scale_milli)
            && self
                .margin_left_microns
                .checked_add(self.margin_right_microns)
                .is_some_and(|v| v < self.width_microns)
            && self
                .margin_top_microns
                .checked_add(self.margin_bottom_microns)
                .is_some_and(|v| v < self.height_microns)
            && self.page_ranges.len() <= 256
            && (self.page_ranges.is_empty()
                || self.page_ranges.split(',').all(|range| {
                    let mut bounds = range.trim().split('-');
                    let first = bounds.next().and_then(|v| v.trim().parse::<u32>().ok());
                    let last = bounds
                        .next()
                        .map(|v| v.trim().parse::<u32>().ok())
                        .unwrap_or(first);
                    bounds.next().is_none()
                        && first
                            .zip(last)
                            .is_some_and(|(first, last)| first > 0 && first <= last && last <= 1000)
                }))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScrapeOptions {
    pub html: bool,
    pub text: bool,
    pub metadata: bool,
    pub links: bool,
    pub accessibility: bool,
    pub max_nodes: u32,
    pub max_output_bytes: u64,
    pub delivery: CaptureDelivery,
}
impl Default for ScrapeOptions {
    fn default() -> Self {
        Self {
            html: false,
            text: true,
            metadata: true,
            links: true,
            accessibility: false,
            max_nodes: 3000,
            max_output_bytes: 1024 * 1024,
            delivery: CaptureDelivery::Artifact,
        }
    }
}
impl ScrapeOptions {
    #[must_use]
    pub fn validate(&self) -> bool {
        (self.html || self.text || self.metadata || self.links || self.accessibility)
            && (1..=3000).contains(&self.max_nodes)
            && (1024..=1024 * 1024).contains(&self.max_output_bytes)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureCommand {
    Screenshot {
        #[serde(default)]
        options: ScreenshotOptions,
    },
    Pdf {
        #[serde(default)]
        options: PdfOptions,
    },
    Scrape {
        #[serde(default)]
        options: ScrapeOptions,
    },
}
impl CaptureCommand {
    #[must_use]
    pub fn validate(&self) -> bool {
        match self {
            Self::Screenshot { options } => options.validate(),
            Self::Pdf { options } => options.validate(),
            Self::Scrape { options } => options.validate(),
        }
    }
    #[must_use]
    pub fn maximum_bytes(&self) -> u64 {
        match self {
            Self::Screenshot { .. } => MAX_SCREENSHOT_BYTES,
            Self::Pdf { .. } => MAX_CAPTURE_BYTES,
            Self::Scrape { options } => options.max_output_bytes,
        }
    }
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        match self {
            Self::Screenshot { options } => options.content_type(),
            Self::Pdf { .. } => "application/pdf",
            Self::Scrape { .. } => "application/json",
        }
    }
    #[must_use]
    pub const fn admission_class(&self) -> crate::AdmissionClass {
        match self {
            Self::Screenshot { .. } => crate::AdmissionClass::FullPageScreenshot,
            Self::Pdf { .. } => crate::AdmissionClass::Pdf,
            Self::Scrape { .. } => crate::AdmissionClass::Scrape,
        }
    }
}
