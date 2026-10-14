use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use browserd_artifacts::{ArtifactChecksum, ArtifactContentSource};
use browserd_core::{PageId, SessionId};
use browserd_features::{
    BoundedByteStream, CAPTURE_CHUNK_BYTES, CaptureCommand, CaptureDelivery,
    MAX_INLINE_CAPTURE_BYTES, PdfLimits, PdfRequest, ScreenshotFormat, ScreenshotLimits,
    ScreenshotRequest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{ChromiumOwnerActor, GuardedPageExecution, OwnerActorError, PageExecutionFence};
use crate::{
    GeneratedArtifactRequest, GeneratedArtifactSink, GeneratedCaptureResult, SandboxClient,
    TargetManagerDrain,
};

impl<D: TargetManagerDrain> ChromiumOwnerActor<D> {
    async fn capture_cdp(
        &mut self,
        method: &'static str,
        params: Value,
        session: &str,
        guarded: Option<GuardedPageExecution>,
        deadline: Instant,
    ) -> Result<Value, OwnerActorError> {
        self.command_event_first(
            method,
            params,
            Some(session.to_owned()),
            None,
            guarded,
            Some(deadline),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn capture_page(
        &mut self,
        session_id: &SessionId,
        page_id: &PageId,
        command: CaptureCommand,
        request: GeneratedArtifactRequest,
        store: Arc<dyn SandboxClient>,
        deadline: Instant,
    ) -> Result<GeneratedCaptureResult, OwnerActorError> {
        if !command.validate() || Instant::now() >= deadline {
            return Err(OwnerActorError::Rejected);
        }
        let (_, target_id, route) = self.owned_page_route(session_id, page_id)?;
        if route.tenant_id() != request.key().tenant_id()
            || route.ownership_fence() != request.fence()
            || request.key().session_id() != session_id
            || request.content_type() != command.content_type()
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        let cdp_session = route.session_id().to_owned();
        let before = self.node_document_state(&target_id)?;
        let guarded = Some(GuardedPageExecution {
            viewer_transform: None,
            target_id,
            fence: PageExecutionFence {
                target_incarnation: before.target_incarnation.get(),
                frame_document_epoch: before.frame_document_epoch.get(),
                url_revision: before.url_revision,
            },
        });
        let deadline = deadline
            .min(Instant::now() + Duration::from_secs(60))
            .checked_sub(Duration::from_millis(50))
            .ok_or(OwnerActorError::DeadlineBeforeDispatch)?;
        match command {
            CaptureCommand::Screenshot { options } => {
                let metrics = self
                    .capture_cdp(
                        "Page.getLayoutMetrics",
                        json!({}),
                        &cdp_session,
                        guarded.clone(),
                        deadline,
                    )
                    .await?;
                let viewport = metrics
                    .get("cssLayoutViewport")
                    .ok_or(OwnerActorError::Rejected)?;
                let content = metrics
                    .get("cssContentSize")
                    .ok_or(OwnerActorError::Rejected)?;
                let dpr = self
                    .context_by_session
                    .get(session_id)
                    .and_then(|id| self.contexts.get(id))
                    .and_then(|entry| entry.options.as_ref())
                    .map_or(1, |options| options.viewport.device_scale_factor);
                let (x, y, width, height) = if let Some(clip) = options.clip {
                    (
                        f64::from(clip.x),
                        f64::from(clip.y),
                        f64::from(clip.width),
                        f64::from(clip.height),
                    )
                } else if options.full_page {
                    (
                        0.0,
                        0.0,
                        number(content, "width")?,
                        number(content, "height")?,
                    )
                } else {
                    (
                        number(viewport, "pageX")?,
                        number(viewport, "pageY")?,
                        number(viewport, "clientWidth")?,
                        number(viewport, "clientHeight")?,
                    )
                };
                if x + width > number(content, "width")? || y + height > number(content, "height")?
                {
                    return Err(OwnerActorError::Rejected);
                }
                let pixel_width = bounded_dimension(width * f64::from(dpr))?;
                let pixel_height = bounded_dimension(height * f64::from(dpr))?;
                ScreenshotLimits {
                    max_width: 4096,
                    max_height: 16384,
                    max_pixels: 16_777_216,
                    max_encoded_bytes: request.max_bytes(),
                    max_capture_time: Duration::from_secs(60),
                }
                .preflight(ScreenshotRequest {
                    width: pixel_width,
                    height: pixel_height,
                    capture_timeout: deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_secs(60)),
                })
                .map_err(|_| OwnerActorError::Rejected)?;
                let mut params = json!({"format":match options.format {ScreenshotFormat::Png=>"png",ScreenshotFormat::Jpeg=>"jpeg"},
                    "fromSurface":true,"captureBeyondViewport": options.full_page || options.clip.is_some(),
                    "clip":{"x":x,"y":y,"width":width,"height":height,"scale":1}});
                if let Some(quality) = options.quality {
                    params["quality"] = json!(quality);
                }
                let mut sink = store
                    .begin_generated_artifact(&request)
                    .map_err(|_| OwnerActorError::Rejected)?;
                let _ = capture_chunk_limit(&mut sink).await?;
                let produced = async {
                    if options.omit_background {
                        self.capture_cdp("Emulation.setDefaultBackgroundColorOverride",json!({"color":{"r":0,"g":0,"b":0,"a":0}}),&cdp_session,guarded.clone(),deadline).await?;
                    }
                    let result = self.capture_cdp("Page.captureScreenshot",params,&cdp_session,guarded.clone(),deadline).await;
                    if options.omit_background {
                        // Restoration uses the configured finite CDP command timeout even when the capture deadline expired.
                        self.command_event_first("Emulation.setDefaultBackgroundColorOverride",json!({}),Some(cdp_session),None,None,None).await?;
                    }
                    let result=result?;
                    let data=result.get("data").and_then(Value::as_str).ok_or(OwnerActorError::Rejected)?;
                    let bytes=decode_chunk(data,true,request.max_bytes())?;
                    if bytes.is_empty() {return Err(OwnerActorError::Rejected);}
                    let metadata=json!({"width":pixel_width,"height":pixel_height,"device_scale_factor":dpr,
                        "viewport":{"width":number(viewport,"clientWidth")?,"height":number(viewport,"clientHeight")?},
                        "screenshot_inline_fallback":options.delivery==CaptureDelivery::Inline && bytes.len()>MAX_INLINE_CAPTURE_BYTES});
                    Ok((bytes,metadata,data.to_owned()))
                }.await;
                let (bytes, metadata, data) = match produced {
                    Ok(produced) => produced,
                    Err(error) => {
                        abort_sink(&mut sink).await;
                        return Err(error);
                    }
                };
                if options.delivery == CaptureDelivery::Inline
                    && bytes.len() <= MAX_INLINE_CAPTURE_BYTES
                {
                    abort_sink(&mut sink).await;
                    return inline_result(
                        json!({"screenshot_inline":data,"content_type":request.content_type(),"capture":metadata}),
                    );
                }
                store_bytes(sink, request, &bytes, metadata, deadline).await
            }
            CaptureCommand::Pdf { options } => {
                let metrics = self
                    .capture_cdp(
                        "Page.getLayoutMetrics",
                        json!({}),
                        &cdp_session,
                        guarded.clone(),
                        deadline,
                    )
                    .await?;
                let content = metrics
                    .get("cssContentSize")
                    .ok_or(OwnerActorError::Rejected)?;
                let chunk_bytes = request.max_bytes().min(CAPTURE_CHUNK_BYTES as u64);
                let printable = options.height_microns
                    - options.margin_top_microns
                    - options.margin_bottom_microns;
                let pages = (number(content, "height")? * f64::from(options.scale_milli)
                    / 1000.0
                    / (f64::from(printable) * 96.0 / 25400.0))
                    .ceil()
                    .max(1.0);
                if pages > 1000.0 {
                    return Err(OwnerActorError::Rejected);
                }
                PdfLimits {
                    max_width_microns: 1_000_000,
                    max_height_microns: 1_000_000,
                    max_pages: 1000,
                    max_scale_milli: 2000,
                    max_output_bytes: request.max_bytes(),
                    max_chunk_bytes: chunk_bytes,
                }
                .preflight(&PdfRequest {
                    width_microns: options.width_microns,
                    height_microns: options.height_microns,
                    estimated_pages: pages as u32,
                    scale_milli: options.scale_milli,
                    header: String::new(),
                    footer: String::new(),
                })
                .map_err(|_| OwnerActorError::Rejected)?;
                let mut sink = store
                    .begin_generated_artifact(&request)
                    .map_err(|_| OwnerActorError::Rejected)?;
                let chunk_bytes = chunk_bytes.min(capture_chunk_limit(&mut sink).await? as u64);
                let print = self.capture_cdp("Page.printToPDF",json!({"transferMode":"ReturnAsStream",
                    "landscape":options.landscape,"printBackground":options.print_background,"scale":f64::from(options.scale_milli)/1000.0,
                    "paperWidth":f64::from(options.width_microns)/25400.0,"paperHeight":f64::from(options.height_microns)/25400.0,
                    "marginTop":f64::from(options.margin_top_microns)/25400.0,"marginBottom":f64::from(options.margin_bottom_microns)/25400.0,
                    "marginLeft":f64::from(options.margin_left_microns)/25400.0,"marginRight":f64::from(options.margin_right_microns)/25400.0,
                    "pageRanges":options.page_ranges,"displayHeaderFooter":false,"preferCSSPageSize":false}),&cdp_session,guarded.clone(),deadline).await;
                let handle = match print
                    .as_ref()
                    .ok()
                    .and_then(|value| value.get("stream"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty() && value.len() <= 1024)
                {
                    Some(handle) => handle.to_owned(),
                    None => {
                        abort_sink(&mut sink).await;
                        return Err(OwnerActorError::Rejected);
                    }
                };
                let mut budget = BoundedByteStream::new(request.max_bytes(), chunk_bytes);
                let mut digest = Sha256::new();
                let streamed = async {
                    loop {
                        let chunk = self
                            .capture_cdp(
                                "IO.read",
                                json!({"handle":handle,"size":chunk_bytes}),
                                &cdp_session,
                                guarded.clone(),
                                deadline,
                            )
                            .await?;
                        let data = chunk
                            .get("data")
                            .and_then(Value::as_str)
                            .ok_or(OwnerActorError::Rejected)?;
                        let eof = chunk
                            .get("eof")
                            .and_then(Value::as_bool)
                            .ok_or(OwnerActorError::Rejected)?;
                        let bytes = decode_chunk(
                            data,
                            chunk
                                .get("base64Encoded")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            chunk_bytes,
                        )?;
                        if bytes.is_empty() && !eof {
                            return Err(OwnerActorError::Rejected);
                        }
                        if !bytes.is_empty() {
                            budget
                                .accept_chunk(bytes.len() as u64)
                                .map_err(|_| OwnerActorError::Rejected)?;
                            write_sink(&mut sink, &bytes, deadline).await?;
                            digest.update(&bytes);
                        }
                        if eof {
                            break;
                        }
                    }
                    Ok(())
                }
                .await;
                let closed = self
                    .command_event_first(
                        "IO.close",
                        json!({"handle":handle}),
                        Some(cdp_session),
                        None,
                        None,
                        None,
                    )
                    .await;
                if streamed.is_err() || closed.is_err() {
                    abort_sink(&mut sink).await;
                    return Err(OwnerActorError::Rejected);
                }
                finish_sink(
                    sink,
                    &request,
                    budget.bytes_accepted(),
                    digest.finalize().into(),
                    json!({"estimated_pages":pages}),
                    deadline,
                )
                .await
            }
            CaptureCommand::Scrape { options } => {
                // A fixed internal DOM reader: no supplied JavaScript, no reload/fetch, and no
                // toggling of page script execution. Preflight before constructing HTML/text JSON.
                let expression = format!(
                    r#"(() => {{
                    const o={}; const root=document.documentElement; if(!root) throw Error('empty_document');
                    let nodes=0,estimate=0; const walker=document.createTreeWalker(root,NodeFilter.SHOW_ALL);
                    let n=root; do {{ if(++nodes>o.max_nodes) throw Error('node_budget');
                        if(n.nodeType===3) {{ const v=n.nodeValue||''; if(v.length>8192) throw Error('string_budget'); estimate+=v.length*6; }}
                        if(n.nodeType===1) {{ estimate+=256; if(n.attributes.length>128) throw Error('attribute_budget');
                            for(const a of n.attributes) {{if(a.value.length>8192) throw Error('string_budget');estimate+=(a.name.length+a.value.length)*6+8;}} }}
                        if(estimate>o.max_output_bytes) throw Error('byte_budget');
                    }} while(n=walker.nextNode());
                    const out={{scripts:'unchanged',resources:'not_fetched',nodes}};
                    if(o.html) out.html=root.outerHTML;
                    if(o.text) out.text=(document.body||root).innerText;
                    if(o.metadata) out.metadata={{title:document.title,url:location.href,language:root.lang}};
                    if(o.links) out.links=Array.from(document.querySelectorAll('a[href]')).map(a=>({{text:a.innerText,url:a.href}}));
                    const encoded=JSON.stringify(out); if(new TextEncoder().encode(encoded).length>o.max_output_bytes) throw Error('byte_budget');
                    return encoded;
                }})()"#,
                    serde_json::to_string(&options).map_err(|_| OwnerActorError::Rejected)?
                );
                let preflight_expression =
                    expression.replacen("const out=", "return true; const out=", 1);
                let checked = self.capture_cdp("Runtime.evaluate",json!({"expression":preflight_expression,"returnByValue":true,"awaitPromise":false}),&cdp_session,guarded.clone(),deadline).await?;
                if checked.get("exceptionDetails").is_some()
                    || checked.pointer("/result/value") != Some(&Value::Bool(true))
                {
                    return Err(OwnerActorError::Rejected);
                }
                let mut sink = store
                    .begin_generated_artifact(&request)
                    .map_err(|_| OwnerActorError::Rejected)?;
                let _ = capture_chunk_limit(&mut sink).await?;
                let produced = async {
                let response = self
                    .capture_cdp(
                        "Runtime.evaluate",
                        json!({"expression":expression,"returnByValue":true,"awaitPromise":false}),
                        &cdp_session,
                        guarded.clone(),
                        deadline,
                    )
                    .await?;
                if response.get("exceptionDetails").is_some() {
                    return Err(OwnerActorError::Rejected);
                }
                let raw = response
                    .get("result")
                    .and_then(|value| value.get("value"))
                    .and_then(Value::as_str)
                    .filter(|value| value.len() as u64 <= options.max_output_bytes)
                    .ok_or(OwnerActorError::Rejected)?;
                let mut data: Value =
                    serde_json::from_str(raw).map_err(|_| OwnerActorError::Rejected)?;
                if options.accessibility {
                    let ax = self
                        .capture_cdp(
                            "Accessibility.getFullAXTree",
                            json!({"depth":32}),
                            &cdp_session,
                            guarded,
                            deadline,
                        )
                        .await?;
                    let nodes = ax
                        .get("nodes")
                        .and_then(Value::as_array)
                        .filter(|nodes| nodes.len() <= options.max_nodes as usize)
                        .ok_or(OwnerActorError::Rejected)?;
                    data["accessibility"] = Value::Array(nodes.iter().filter(|node|node.get("ignored")!=Some(&Value::Bool(true)))
                        .map(|node|json!({"role":node.pointer("/role/value"),"name":node.pointer("/name/value"),"value":node.pointer("/value/value")})).collect());
                }
                let bytes = serde_json::to_vec(&data).map_err(|_| OwnerActorError::Rejected)?;
                if bytes.len() as u64 > request.max_bytes() {
                    return Err(OwnerActorError::Rejected);
                }
                Ok((bytes,data))
                }.await;
                let (bytes, data) = match produced {
                    Ok(produced) => produced,
                    Err(error) => {
                        abort_sink(&mut sink).await;
                        return Err(error);
                    }
                };
                if options.delivery == CaptureDelivery::Inline
                    && bytes.len() <= MAX_INLINE_CAPTURE_BYTES
                {
                    abort_sink(&mut sink).await;
                    return inline_result(json!({"scrape":data,"inline_fallback":false}));
                }
                store_bytes(
                    sink,
                    request,
                    &bytes,
                    json!({"inline_fallback":options.delivery==CaptureDelivery::Inline}),
                    deadline,
                )
                .await
            }
        }
    }
}

fn number(value: &Value, key: &str) -> Result<f64, OwnerActorError> {
    value
        .get(key)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or(OwnerActorError::Rejected)
}
fn bounded_dimension(value: f64) -> Result<u32, OwnerActorError> {
    if !value.is_finite() || value <= 0.0 || value > f64::from(u32::MAX) {
        return Err(OwnerActorError::Rejected);
    }
    Ok(value.ceil() as u32)
}
fn decode_chunk(data: &str, encoded: bool, limit: u64) -> Result<Vec<u8>, OwnerActorError> {
    let max = usize::try_from(limit).map_err(|_| OwnerActorError::Rejected)?;
    if data.len()
        > if encoded {
            max.div_ceil(3).saturating_mul(4)
        } else {
            max
        }
    {
        return Err(OwnerActorError::Rejected);
    }
    let bytes = if encoded {
        BASE64.decode(data).map_err(|_| OwnerActorError::Rejected)?
    } else {
        data.as_bytes().to_vec()
    };
    if bytes.len() > max {
        return Err(OwnerActorError::Rejected);
    }
    Ok(bytes)
}
fn inline_result(value: Value) -> Result<GeneratedCaptureResult, OwnerActorError> {
    let result = serde_json::to_vec(&value).map_err(|_| OwnerActorError::Rejected)?;
    if result.len() > 64 * 1024 {
        return Err(OwnerActorError::Rejected);
    }
    Ok(GeneratedCaptureResult {
        result,
        receipt: None,
        cleanup: None,
    })
}
async fn abort_sink(sink: &mut Box<dyn GeneratedArtifactSink>) {
    let _ = tokio::time::timeout(Duration::from_secs(2), sink.abort()).await;
}
async fn capture_chunk_limit(
    sink: &mut Box<dyn GeneratedArtifactSink>,
) -> Result<usize, OwnerActorError> {
    let limit = sink.max_chunk_bytes().min(CAPTURE_CHUNK_BYTES);
    if limit == 0 {
        abort_sink(sink).await;
        return Err(OwnerActorError::Rejected);
    }
    Ok(limit)
}
async fn write_sink(
    sink: &mut Box<dyn GeneratedArtifactSink>,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), OwnerActorError> {
    tokio::time::timeout_at(deadline.into(), sink.write_chunk(bytes))
        .await
        .map_err(|_| OwnerActorError::Rejected)?
        .map_err(|_| OwnerActorError::Rejected)
}
async fn finish_sink(
    mut sink: Box<dyn GeneratedArtifactSink>,
    request: &GeneratedArtifactRequest,
    size: u64,
    checksum: [u8; 32],
    metadata: Value,
    deadline: Instant,
) -> Result<GeneratedCaptureResult, OwnerActorError> {
    let receipt = match tokio::time::timeout_at(deadline.into(), sink.finish()).await {
        Ok(Ok(receipt)) => receipt,
        _ => {
            abort_sink(&mut sink).await;
            return Err(OwnerActorError::Rejected);
        }
    };
    if receipt.key() != request.key()
        || receipt.source() != ArtifactContentSource::Generated
        || receipt.size_bytes() != size
        || size == 0
        || size > request.max_bytes()
        || receipt.checksum() != &ArtifactChecksum::new(checksum)
        || receipt.detected_content_type() != request.content_type()
        || receipt.scan_verdict().is_some()
        || receipt
            .object_generation()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        abort_sink(&mut sink).await;
        return Err(OwnerActorError::Rejected);
    }
    let result=serde_json::to_vec(&json!({"artifact_id":request.key().artifact_id(),"content_type":request.content_type(),"size_bytes":size,"capture":metadata}))
        .map_err(|_|OwnerActorError::Rejected)?;
    Ok(GeneratedCaptureResult {
        result,
        receipt: Some(receipt),
        cleanup: Some(sink),
    })
}
async fn store_bytes(
    mut sink: Box<dyn GeneratedArtifactSink>,
    request: GeneratedArtifactRequest,
    bytes: &[u8],
    metadata: Value,
    deadline: Instant,
) -> Result<GeneratedCaptureResult, OwnerActorError> {
    if bytes.len() as u64 > request.max_bytes() {
        abort_sink(&mut sink).await;
        return Err(OwnerActorError::Rejected);
    }
    let chunk_limit = capture_chunk_limit(&mut sink).await?;
    for chunk in bytes.chunks(chunk_limit) {
        if write_sink(&mut sink, chunk, deadline).await.is_err() {
            abort_sink(&mut sink).await;
            return Err(OwnerActorError::Rejected);
        }
    }
    finish_sink(
        sink,
        &request,
        bytes.len() as u64,
        Sha256::digest(bytes).into(),
        metadata,
        deadline,
    )
    .await
}
