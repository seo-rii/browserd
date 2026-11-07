#![allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "common/live_chromium.rs"]
mod live_chromium;
use browserd_worker::{ChromiumDriver, ViewerClientMessage, WorkerViewerFrame};
use live_chromium::LiveChromium;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

async fn frame(live: &LiveChromium) -> WorkerViewerFrame {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let driver = live.driver.clone();
        let session = live.session.clone();
        let page = live.page.clone();
        let fence = live.fence.clone();
        if let Some(frame) =
            tokio::task::spawn_blocking(move || driver.viewer_frame(&session, &page, &fence))
                .await
                .unwrap()
                .unwrap()
        {
            return frame;
        }
        assert!(Instant::now() < deadline, "real screencast frame deadline");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
async fn input(live: &LiveChromium, epoch: u64, sequence: u64, mut message: Value) {
    message["page_id"] = json!(live.page);
    message["frame_transform_id"] = json!(epoch);
    message["lease_epoch"] = json!(1);
    message["input_sequence"] = json!(sequence);
    let message: ViewerClientMessage = serde_json::from_value(message).unwrap();
    let driver = live.driver.clone();
    let session = live.session.clone();
    let page = live.page.clone();
    let fence = live.fence.clone();
    tokio::task::spawn_blocking(move || {
        driver.viewer_input(&session, &page, &fence, epoch, &message)
    })
    .await
    .unwrap()
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit sandbox-enabled BROWSERD_TEST_CHROMIUM"]
async fn real_owner_screencast_shared_frame_pointer_and_korean_composition() {
    let live = LiveChromium::start().await;
    live.evaluate("document.body.innerHTML='<input id=entry><button id=button style=\"position:absolute;left:100px;top:100px;width:80px;height:30px\">click</button>'; window.clicks=0; button.onclick=()=>clicks++; true").await;
    let driver = live.driver.clone();
    let session = live.session.clone();
    let page = live.page.clone();
    let fence = live.fence.clone();
    tokio::task::spawn_blocking(move || driver.viewer_start(&session, &page, &fence))
        .await
        .unwrap()
        .unwrap();
    // Chromium must keep producing/ACKing before any client polls the owner.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let first = frame(&live).await;
    assert!(!first.jpeg_base64.is_empty());
    let metadata: Value = serde_json::from_slice(&first.metadata).unwrap();
    assert!(metadata["width"].as_f64().unwrap() > 200.0);
    assert_eq!(
        frame(&live).await.frame_transform_id,
        first.frame_transform_id
    );
    input(
        &live,
        first.frame_transform_id,
        1,
        json!({"type":"mouse","phase":"down","button":"left","buttons":1,"x":125,"y":115}),
    )
    .await;
    input(
        &live,
        first.frame_transform_id,
        2,
        json!({"type":"mouse","phase":"up","button":"left","buttons":0,"x":125,"y":115}),
    )
    .await;
    assert_eq!(live.evaluate("clicks").await, 1);
    live.evaluate("entry.focus(); true").await;
    input(
        &live,
        first.frame_transform_id,
        3,
        json!({"type":"composition_start"}),
    )
    .await;
    input(
        &live,
        first.frame_transform_id,
        4,
        json!({"type":"composition_update","text":"한"}),
    )
    .await;
    input(
        &live,
        first.frame_transform_id,
        5,
        json!({"type":"composition_update","text":"한글"}),
    )
    .await;
    input(
        &live,
        first.frame_transform_id,
        6,
        json!({"type":"composition_commit","text":"한글"}),
    )
    .await;
    assert_eq!(live.evaluate("entry.value").await, "한글");
    live.evaluate("document.body.innerHTML='<textarea id=entry>a</textarea>'; entry.focus(); entry.selectionStart=entry.selectionEnd=1; true").await;
    input(
        &live,
        first.frame_transform_id,
        7,
        json!({"type":"key","phase":"down","key":"Enter","code":"Enter"}),
    )
    .await;
    input(
        &live,
        first.frame_transform_id,
        8,
        json!({"type":"key","phase":"up","key":"Enter","code":"Enter"}),
    )
    .await;
    assert_eq!(live.evaluate("entry.value").await, "a\n");
    let driver = live.driver.clone();
    let session = live.session.clone();
    let page = live.page.clone();
    let fence = live.fence.clone();
    tokio::task::spawn_blocking(move || driver.viewer_stop(&session, &page, &fence))
        .await
        .unwrap()
        .unwrap();
}
