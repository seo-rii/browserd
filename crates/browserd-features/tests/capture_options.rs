use browserd_features::{
    CaptureDelivery, PdfOptions, ScrapeOptions, ScreenshotClip, ScreenshotFormat, ScreenshotOptions,
};

#[test]
fn screenshot_preflight_rejects_invalid_geometry_and_format_options() {
    let mut options = ScreenshotOptions::default();
    assert!(options.validate());
    options.format = ScreenshotFormat::Png;
    options.quality = Some(80);
    assert!(
        !options.validate(),
        "PNG quality must not be silently ignored"
    );
    options.quality = None;
    options.clip = Some(ScreenshotClip {
        x: 0,
        y: 0,
        width: 0,
        height: 100,
    });
    assert!(!options.validate());
    options.clip = Some(ScreenshotClip {
        x: 0,
        y: 0,
        width: 100,
        height: 100,
    });
    options.full_page = true;
    assert!(
        !options.validate(),
        "clip and full-page are mutually exclusive"
    );
}

#[test]
fn pdf_options_reject_unbounded_ranges_and_impossible_printable_area() {
    let mut options = PdfOptions::default();
    assert!(options.validate());
    options.page_ranges = "1-99999999999999".to_owned();
    assert!(!options.validate());
    options.page_ranges = "1-3,5".to_owned();
    assert!(options.validate());
    options.margin_left_microns = options.width_microns;
    assert!(!options.validate());
}

#[test]
fn scrape_requires_an_explicit_bounded_supported_profile() {
    let mut options = ScrapeOptions::default();
    assert!(options.validate());
    options.delivery = CaptureDelivery::Inline;
    options.max_nodes = 0;
    assert!(!options.validate());
    options.max_nodes = 10;
    options.max_output_bytes = u64::MAX;
    assert!(!options.validate());
}
