use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightError {
    InvalidLimits,
    InvalidGeometry,
    DimensionsExceeded,
    PixelCountExceeded,
    CaptureTimeoutExceeded,
    PageCountExceeded,
    ScaleExceeded,
    TemplateDenied,
    StringTooLarge,
    NodeCountExceeded,
    ResultTooLarge,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScreenshotRequest {
    pub width: u32,
    pub height: u32,
    pub capture_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScreenshotLimits {
    pub max_width: u32,
    pub max_height: u32,
    pub max_pixels: u64,
    pub max_encoded_bytes: u64,
    pub max_capture_time: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreflightReceipt {
    pub maximum_output_bytes: u64,
    pub maximum_chunk_bytes: u64,
}

impl ScreenshotLimits {
    pub fn preflight(self, request: ScreenshotRequest) -> Result<PreflightReceipt, PreflightError> {
        if self.max_width == 0
            || self.max_height == 0
            || self.max_pixels == 0
            || self.max_encoded_bytes == 0
            || self.max_capture_time.is_zero()
        {
            return Err(PreflightError::InvalidLimits);
        }
        if request.width == 0 || request.height == 0 || request.capture_timeout.is_zero() {
            return Err(PreflightError::InvalidGeometry);
        }
        if request.width > self.max_width || request.height > self.max_height {
            return Err(PreflightError::DimensionsExceeded);
        }
        let pixels = u64::from(request.width)
            .checked_mul(u64::from(request.height))
            .ok_or(PreflightError::ArithmeticOverflow)?;
        if pixels > self.max_pixels {
            return Err(PreflightError::PixelCountExceeded);
        }
        if request.capture_timeout > self.max_capture_time {
            return Err(PreflightError::CaptureTimeoutExceeded);
        }
        Ok(PreflightReceipt {
            maximum_output_bytes: self.max_encoded_bytes,
            maximum_chunk_bytes: self.max_encoded_bytes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PdfRequest {
    pub width_microns: u32,
    pub height_microns: u32,
    pub estimated_pages: u32,
    pub scale_milli: u32,
    pub header: String,
    pub footer: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PdfLimits {
    pub max_width_microns: u32,
    pub max_height_microns: u32,
    pub max_pages: u32,
    pub max_scale_milli: u32,
    pub max_output_bytes: u64,
    pub max_chunk_bytes: u64,
}

impl PdfLimits {
    pub fn preflight(&self, request: &PdfRequest) -> Result<PreflightReceipt, PreflightError> {
        if self.max_width_microns == 0
            || self.max_height_microns == 0
            || self.max_pages == 0
            || self.max_scale_milli < 100
            || self.max_output_bytes == 0
            || self.max_chunk_bytes == 0
            || self.max_chunk_bytes > self.max_output_bytes
        {
            return Err(PreflightError::InvalidLimits);
        }
        if request.width_microns == 0 || request.height_microns == 0 {
            return Err(PreflightError::InvalidGeometry);
        }
        if request.width_microns > self.max_width_microns
            || request.height_microns > self.max_height_microns
        {
            return Err(PreflightError::DimensionsExceeded);
        }
        if request.estimated_pages == 0 || request.estimated_pages > self.max_pages {
            return Err(PreflightError::PageCountExceeded);
        }
        if request.scale_milli < 100 || request.scale_milli > self.max_scale_milli {
            return Err(PreflightError::ScaleExceeded);
        }
        for template in [&request.header, &request.footer] {
            if template.len() > 1_024 || template.contains(['<', '>']) {
                return Err(PreflightError::TemplateDenied);
            }
            let remaining = template
                .replace("{title}", "")
                .replace("{url}", "")
                .replace("{date}", "")
                .replace("{pageNumber}", "")
                .replace("{totalPages}", "");
            if remaining.contains(['{', '}']) || remaining.chars().any(char::is_control) {
                return Err(PreflightError::TemplateDenied);
            }
        }
        Ok(PreflightReceipt {
            maximum_output_bytes: self.max_output_bytes,
            maximum_chunk_bytes: self.max_chunk_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByteBudgetError {
    InvalidLimit,
    ChunkTooLarge,
    TotalTooLarge,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundedByteStream {
    maximum_total: u64,
    maximum_chunk: u64,
    accepted: u64,
}

impl BoundedByteStream {
    #[must_use]
    pub const fn new(maximum_total: u64, maximum_chunk: u64) -> Self {
        Self {
            maximum_total,
            maximum_chunk,
            accepted: 0,
        }
    }

    pub fn accept_chunk(&mut self, bytes: u64) -> Result<u64, ByteBudgetError> {
        if self.maximum_total == 0
            || self.maximum_chunk == 0
            || self.maximum_chunk > self.maximum_total
            || bytes == 0
        {
            return Err(ByteBudgetError::InvalidLimit);
        }
        if bytes > self.maximum_chunk {
            return Err(ByteBudgetError::ChunkTooLarge);
        }
        let attempted = self
            .accepted
            .checked_add(bytes)
            .ok_or(ByteBudgetError::ArithmeticOverflow)?;
        if attempted > self.maximum_total {
            return Err(ByteBudgetError::TotalTooLarge);
        }
        self.accepted = attempted;
        Ok(attempted)
    }

    #[must_use]
    pub const fn bytes_accepted(self) -> u64 {
        self.accepted
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrapeLimits {
    pub max_nodes: u32,
    pub max_string_bytes: u64,
    pub max_result_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScrapeUsage {
    pub nodes: u32,
    pub result_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScrapeBudget {
    limits: ScrapeLimits,
    usage: ScrapeUsage,
}

impl ScrapeBudget {
    #[must_use]
    pub const fn new(limits: ScrapeLimits) -> Self {
        Self {
            limits,
            usage: ScrapeUsage {
                nodes: 0,
                result_bytes: 0,
            },
        }
    }

    pub fn record_node(&mut self, string_bytes: u64) -> Result<ScrapeUsage, PreflightError> {
        if self.limits.max_nodes == 0
            || self.limits.max_string_bytes == 0
            || self.limits.max_result_bytes == 0
        {
            return Err(PreflightError::InvalidLimits);
        }
        if self.usage.nodes >= self.limits.max_nodes {
            return Err(PreflightError::NodeCountExceeded);
        }
        if string_bytes > self.limits.max_string_bytes {
            return Err(PreflightError::StringTooLarge);
        }
        let nodes = self
            .usage
            .nodes
            .checked_add(1)
            .ok_or(PreflightError::ArithmeticOverflow)?;
        let result_bytes = self
            .usage
            .result_bytes
            .checked_add(string_bytes)
            .ok_or(PreflightError::ArithmeticOverflow)?;
        if result_bytes > self.limits.max_result_bytes {
            return Err(PreflightError::ResultTooLarge);
        }
        self.usage = ScrapeUsage {
            nodes,
            result_bytes,
        };
        Ok(self.usage)
    }

    #[must_use]
    pub const fn usage(self) -> ScrapeUsage {
        self.usage
    }
}
