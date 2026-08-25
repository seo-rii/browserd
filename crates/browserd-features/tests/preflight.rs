use std::time::Duration;

use browserd_features::{
    BoundedByteStream, ByteBudgetError, PdfLimits, PdfRequest, PreflightError, ScrapeBudget,
    ScrapeLimits, ScreenshotLimits, ScreenshotRequest,
};

#[test]
fn screenshot_preflight_checks_dimensions_pixels_time_and_encoded_budget() {
    let limits = ScreenshotLimits {
        max_width: 4_000,
        max_height: 4_000,
        max_pixels: 8_000_000,
        max_encoded_bytes: 2_000_000,
        max_capture_time: Duration::from_secs(10),
    };
    assert!(
        limits
            .preflight(ScreenshotRequest {
                width: 2_000,
                height: 3_000,
                capture_timeout: Duration::from_secs(9),
            })
            .is_ok()
    );
    assert_eq!(
        limits.preflight(ScreenshotRequest {
            width: 4_001,
            height: 1,
            capture_timeout: Duration::from_secs(1),
        }),
        Err(PreflightError::DimensionsExceeded)
    );
    assert_eq!(
        limits.preflight(ScreenshotRequest {
            width: 3_000,
            height: 3_000,
            capture_timeout: Duration::from_secs(1),
        }),
        Err(PreflightError::PixelCountExceeded)
    );
    assert_eq!(
        limits.preflight(ScreenshotRequest {
            width: u32::MAX,
            height: u32::MAX,
            capture_timeout: Duration::from_secs(11),
        }),
        Err(PreflightError::DimensionsExceeded)
    );
}

#[test]
fn pdf_preflight_rejects_unbounded_geometry_scale_pages_and_templates() {
    let limits = PdfLimits {
        max_width_microns: 500_000,
        max_height_microns: 500_000,
        max_pages: 200,
        max_scale_milli: 2_000,
        max_output_bytes: 10_000,
        max_chunk_bytes: 1_024,
    };
    let valid = PdfRequest {
        width_microns: 210_000,
        height_microns: 297_000,
        estimated_pages: 20,
        scale_milli: 1_000,
        header: "{title}".to_owned(),
        footer: "{pageNumber}/{totalPages}".to_owned(),
    };
    assert!(limits.preflight(&valid).is_ok());

    let mut arbitrary_html = valid.clone();
    arbitrary_html.header = "<script>alert(1)</script>".to_owned();
    assert_eq!(
        limits.preflight(&arbitrary_html),
        Err(PreflightError::TemplateDenied)
    );
    let mut too_many_pages = valid;
    too_many_pages.estimated_pages = 201;
    assert_eq!(
        limits.preflight(&too_many_pages),
        Err(PreflightError::PageCountExceeded)
    );
}

#[test]
fn streamed_feature_output_rejects_a_chunk_or_total_before_mutating_usage() {
    let mut stream = BoundedByteStream::new(10, 6);
    assert_eq!(stream.accept_chunk(6), Ok(6));
    assert_eq!(stream.accept_chunk(7), Err(ByteBudgetError::ChunkTooLarge));
    assert_eq!(stream.bytes_accepted(), 6);
    assert_eq!(stream.accept_chunk(4), Ok(10));
    assert_eq!(stream.accept_chunk(1), Err(ByteBudgetError::TotalTooLarge));
    assert_eq!(stream.bytes_accepted(), 10);
}

#[test]
fn scrape_budget_is_all_or_nothing_for_each_observation() {
    let mut budget = ScrapeBudget::new(ScrapeLimits {
        max_nodes: 2,
        max_string_bytes: 5,
        max_result_bytes: 8,
    });
    assert!(budget.record_node(3).is_ok());
    assert_eq!(budget.record_node(6), Err(PreflightError::StringTooLarge));
    assert_eq!(budget.usage().nodes, 1);
    assert_eq!(budget.usage().result_bytes, 3);
    assert!(budget.record_node(5).is_ok());
    assert_eq!(
        budget.record_node(0),
        Err(PreflightError::NodeCountExceeded)
    );
    assert_eq!(budget.usage().nodes, 2);
    assert_eq!(budget.usage().result_bytes, 8);
}
