use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::sync::mpsc;

const BOUND: Duration = Duration::from_secs(3);

#[derive(Default)]
struct Gate {
    released: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn wait(&self) {
        let (released, _) = self
            .changed
            .wait_timeout_while(self.released.lock().unwrap(), BOUND, |released| !*released)
            .unwrap();
        assert!(
            *released,
            "test must release a blocked backend within its bound"
        );
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Submit,
    Accepted,
    Submitted,
    Poll,
    Polled,
}

#[derive(Clone, Copy)]
enum Poll {
    Queued,
    Unknown,
    Error,
    WrongAction,
}

struct WaitService {
    session: SessionId,
    receipt: ActionSnapshot,
    poll: Poll,
    submit_before: Option<Arc<Gate>>,
    submit_after: Option<Arc<Gate>>,
    submit_succeeds: AtomicBool,
    poll_gate: Option<Arc<Gate>>,
    submit_calls: AtomicUsize,
    poll_calls: AtomicUsize,
    cancel_calls: AtomicUsize,
    trace: mpsc::UnboundedSender<Event>,
}

impl WaitService {
    fn terminal_receipt(&self, action_id: ActionId, success: bool) -> ActionSnapshot {
        let (terminal_detail, result_content) = if success {
            (
                TerminalDetail::Succeeded(ResultDigest::new([9; 32])),
                Some(br#"{"value":"complete"}"#.to_vec()),
            )
        } else {
            (
                TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost),
                None,
            )
        };
        ActionSnapshot::from_facts(ActionSnapshotFacts {
            action_id,
            action_sequence: self.receipt.action_sequence(),
            idempotency_key: self.receipt.request().idempotency_key().clone(),
            canonical_request_hash: self.receipt.request().canonical_request_hash(),
            kind: self.receipt.request().kind(),
            state: terminal_detail.state(),
            dispatch_acknowledged: false,
            approval_decision: None,
            terminal_detail: Some(terminal_detail),
            resolution: None,
            result_content,
        })
        .unwrap()
    }

    fn submit(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
        accepted: &mut (dyn FnMut(ApiEnvelope<ActionSnapshot>) + Send),
    ) -> Result<ApiResponse, ApiError> {
        request.authorize(principal)?;
        request.validate()?;
        let ApiRequest::SubmitAction(command) = request else {
            return self.execute(principal, request);
        };
        assert_eq!(command.session_id, self.session);
        self.submit_calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.trace.send(Event::Submit);
        if let Some(gate) = &self.submit_before {
            gate.wait();
        }
        accepted(ApiEnvelope::new(self.receipt.clone()));
        let _ = self.trace.send(Event::Accepted);
        if let Some(gate) = &self.submit_after {
            gate.wait();
        }
        let _ = self.trace.send(Event::Submitted);
        let receipt = if self.submit_succeeds.load(Ordering::SeqCst) {
            self.terminal_receipt(self.receipt.action_id().clone(), true)
        } else {
            self.receipt.clone()
        };
        Ok(ApiResponse::Action(ApiEnvelope::new(receipt)))
    }
}

impl ApiService for WaitService {
    fn execute(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        request.authorize(principal)?;
        request.validate()?;
        match request {
            ApiRequest::SubmitAction(_) => self.submit(principal, request, &mut |_| {}),
            ApiRequest::GetAction(command) => {
                assert_eq!(command.session_id, self.session);
                assert_eq!(&command.action_id, self.receipt.action_id());
                self.poll_calls.fetch_add(1, Ordering::SeqCst);
                let _ = self.trace.send(Event::Poll);
                if let Some(gate) = &self.poll_gate {
                    gate.wait();
                }
                let _ = self.trace.send(Event::Polled);
                let snapshot = match self.poll {
                    Poll::Queued => self.receipt.clone(),
                    Poll::Unknown => self.terminal_receipt(self.receipt.action_id().clone(), false),
                    Poll::WrongAction => self.terminal_receipt(ActionId::new(), false),
                    Poll::Error => {
                        return Err(ApiError::new(ErrorCode::WorkerUnavailable, "fixture poll"));
                    }
                };
                Ok(ApiResponse::Action(ApiEnvelope::new(snapshot)))
            }
            ApiRequest::CancelAction(_) => {
                self.cancel_calls.fetch_add(1, Ordering::SeqCst);
                Err(ApiError::invalid_request(
                    "wait must never cancel the action",
                ))
            }
            ApiRequest::GetSession(_) => {
                Err(ApiError::new(ErrorCode::SessionNotFound, "fixture read"))
            }
            _ => Err(ApiError::invalid_request("unexpected wait fixture request")),
        }
    }

    fn execute_with_action_acceptance(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
        accepted: &mut (dyn FnMut(ApiEnvelope<ActionSnapshot>) + Send),
    ) -> Result<ApiResponse, ApiError> {
        self.submit(principal, request, accepted)
    }
}

struct Tenants(Vec<AuthenticatedPrincipal>);

struct LegacyService(Arc<WaitService>);

impl ApiService for LegacyService {
    fn execute(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        self.0.execute(principal, request)
    }
}

impl Authenticator for Tenants {
    fn authenticate(&self, bearer: &str) -> Result<AuthenticatedPrincipal, AuthenticationError> {
        bearer
            .parse::<usize>()
            .ok()
            .and_then(|index| self.0.get(index))
            .cloned()
            .ok_or(AuthenticationError)
    }
}

struct Fixture {
    app: axum::Router,
    service: Arc<WaitService>,
    events: mpsc::UnboundedReceiver<Event>,
}

impl Fixture {
    fn new(
        config: HttpConfig,
        scopes: &[&str],
        poll: Poll,
        before: Option<Arc<Gate>>,
        after: Option<Arc<Gate>>,
        poll_gate: Option<Arc<Gate>>,
    ) -> Self {
        let (trace, events) = mpsc::unbounded_channel();
        let receipt = ActionSnapshot::from_facts(ActionSnapshotFacts {
            action_id: ActionId::new(),
            action_sequence: ActionSequence::new(42),
            idempotency_key: IdempotencyKey::new(Uuid::new_v4().to_string()),
            canonical_request_hash: CanonicalRequestHash::new([7; 32]),
            kind: ActionKind::ReadOnly,
            state: ActionState::Queued,
            dispatch_acknowledged: false,
            approval_decision: None,
            terminal_detail: None,
            resolution: None,
            result_content: None,
        })
        .unwrap();
        let service = Arc::new(WaitService {
            session: SessionId::new(),
            receipt,
            poll,
            submit_before: before,
            submit_after: after,
            submit_succeeds: AtomicBool::new(false),
            poll_gate,
            submit_calls: AtomicUsize::new(0),
            poll_calls: AtomicUsize::new(0),
            cancel_calls: AtomicUsize::new(0),
            trace,
        });
        let app = router(
            config,
            service.clone(),
            Arc::new(Tenants(
                (0..3).map(|_| principal(scopes).unwrap()).collect(),
            )),
            Arc::new(RejectViewer),
            Arc::new(StaticReadiness(true)),
        );
        Self {
            app,
            service,
            events,
        }
    }

    fn request(&self, tenant: usize, prefer: Option<&str>) -> Request<Body> {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/sessions/{}/actions", self.service.session))
            .header("authorization", format!("Bearer {tenant}"))
            .header("content-type", "application/json")
            .header("idempotency-key", Uuid::new_v4().to_string());
        if let Some(prefer) = prefer {
            request = request.header("prefer", prefer);
        }
        request
            .body(Body::from(
                serde_json::json!({
                    "page_id":browserd_core::PageId::new(), "if_session_incarnation":1,
                    "execution_timeout_ms":30000,"action":{"type":"get_url"}
                })
                .to_string(),
            ))
            .unwrap()
    }

    async fn post(&self, tenant: usize, prefer: Option<&str>) -> axum::response::Response {
        tokio::time::timeout(
            BOUND,
            self.app.clone().oneshot(self.request(tenant, prefer)),
        )
        .await
        .expect("bounded HTTP response")
        .unwrap()
    }

    async fn event(&mut self, expected: Event) {
        tokio::time::timeout(BOUND, async {
            loop {
                if self.events.recv().await.expect("fixture event") == expected {
                    break;
                }
            }
        })
        .await
        .expect("bounded backend progress");
    }

    async fn eventually_applied(&self, tenant: usize, prefer: &str) {
        // Backend notifications precede return from the blocking closure, whose guards are
        // private to the transport. Observe their eventual release with bounded backoff rather
        // than assuming that receiving a backend notification already released those guards.
        tokio::time::timeout(BOUND, async {
            loop {
                let response = self.post(tenant, Some(prefer)).await;
                if response.status() != StatusCode::SERVICE_UNAVAILABLE {
                    let applied = response
                        .headers()
                        .get("preference-applied")
                        .map(|value| value.to_str().unwrap());
                    assert!(applied.is_none() || applied == Some(prefer));
                    self.assert_accepted(&response, applied);
                    if response
                        .headers()
                        .get("preference-applied")
                        .is_some_and(|value| value == prefer)
                    {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("finished backend jobs must release admission capacity");
    }

    async fn session_read(&self) -> axum::response::Response {
        tokio::time::timeout(
            BOUND,
            self.app.clone().oneshot(
                Request::builder()
                    .uri(format!("/v1/sessions/{}", self.service.session))
                    .header("authorization", "Bearer 0")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap()
    }

    fn assert_accepted(&self, response: &axum::response::Response, applied: Option<&str>) {
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.headers()["location"],
            format!(
                "/v1/sessions/{}/actions/{}",
                self.service.session,
                self.service.receipt.action_id()
            )
        );
        assert_eq!(
            response
                .headers()
                .get("preference-applied")
                .map(|value| value.to_str().unwrap()),
            applied
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for gate in [
            &self.service.submit_before,
            &self.service.submit_after,
            &self.service.poll_gate,
        ]
        .into_iter()
        .flatten()
        {
            gate.release();
        }
    }
}

fn ordinary_fixture(poll: Poll) -> Fixture {
    Fixture::new(
        HttpConfig::default(),
        &["browser:act", "session:read"],
        poll,
        None,
        None,
        None,
    )
}

#[tokio::test]
async fn malformed_prefer_rejects_before_any_submission() {
    let fixture = ordinary_fixture(Poll::Queued);
    for value in [
        "wait=",
        "wait=+1",
        "wait=-1",
        "wait=1.0",
        "wait= 1",
        "wait=1 ",
        "Wait=1",
        "wait=30001",
        "wait=184467440737095516160",
        "wait=1,respond-async",
        "wait=1;foo=bar",
    ] {
        assert_eq!(
            fixture.post(0, Some(value)).await.status(),
            StatusCode::BAD_REQUEST,
            "{value}"
        );
    }
    let mut duplicate = fixture.request(0, Some("wait=0"));
    duplicate
        .headers_mut()
        .append("prefer", http::HeaderValue::from_static("wait=1"));
    assert_eq!(
        fixture
            .app
            .clone()
            .oneshot(duplicate)
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut non_ascii = fixture.request(0, None);
    non_ascii.headers_mut().insert(
        "prefer",
        http::HeaderValue::from_bytes(b"wait=\xff").unwrap(),
    );
    assert_eq!(
        fixture
            .app
            .clone()
            .oneshot(non_ascii)
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(fixture.service.submit_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.service.poll_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn zero_wait_and_no_header_never_poll_or_repeat_submit() {
    let fixture = ordinary_fixture(Poll::Unknown);
    let zero = fixture.post(0, Some("wait=0")).await;
    fixture.assert_accepted(&zero, Some("wait=0"));
    let normal = fixture.post(0, None).await;
    assert_eq!(normal.status(), StatusCode::ACCEPTED);
    assert!(normal.headers().get("preference-applied").is_none());
    assert_eq!(fixture.service.submit_calls.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.service.poll_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.service.cancel_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn positive_wait_without_session_read_preserves_submit_only_authority() {
    let fixture = Fixture::new(
        HttpConfig::default(),
        &["browser:act"],
        Poll::Unknown,
        None,
        None,
        None,
    );
    let response = fixture.post(0, Some("wait=30000")).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(response.headers().get("preference-applied").is_none());
    assert_eq!(fixture.service.submit_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.service.poll_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn wait_observes_outcome_unknown_as_terminal_200_without_reexecution() {
    let fixture = ordinary_fixture(Poll::Unknown);
    let response = fixture.post(0, Some("wait=30000")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["preference-applied"], "wait=30000");
    let body = body_json(response).await;
    assert_eq!(
        body["data"]["action_id"],
        fixture.service.receipt.action_id().to_string()
    );
    assert_eq!(body["data"]["status"], "outcome_unknown");
    assert_eq!(body["data"]["retryable"], false);
    assert_eq!(fixture.service.submit_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.service.poll_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.service.cancel_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn timeout_poll_error_and_wrong_action_preserve_the_accepted_receipt() {
    for poll in [Poll::Queued, Poll::Error, Poll::WrongAction] {
        let fixture = ordinary_fixture(poll);
        let response = fixture.post(0, Some("wait=200")).await;
        fixture.assert_accepted(&response, Some("wait=200"));
        let body = body_json(response).await;
        assert_eq!(
            body["data"]["action_id"],
            fixture.service.receipt.action_id().to_string()
        );
        assert_eq!(body["data"]["status"], "queued");
        assert_eq!(fixture.service.submit_calls.load(Ordering::SeqCst), 1);
        assert!(fixture.service.poll_calls.load(Ordering::SeqCst) > 0);
        assert_eq!(fixture.service.cancel_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn short_positive_wait_expires_before_starting_a_status_lookup() {
    let fixture = ordinary_fixture(Poll::Queued);
    let response = fixture.post(0, Some("wait=20")).await;
    fixture.assert_accepted(&response, Some("wait=20"));
    assert_eq!(fixture.service.submit_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.service.poll_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.service.cancel_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn initial_submit_completion_within_budget_returns_success_and_its_result() {
    let gate = Arc::new(Gate::default());
    let mut fixture = Fixture::new(
        HttpConfig::default(),
        &["browser:act", "session:read"],
        Poll::Queued,
        None,
        Some(gate.clone()),
        None,
    );
    fixture
        .service
        .submit_succeeds
        .store(true, Ordering::SeqCst);
    let task = tokio::spawn(
        fixture
            .app
            .clone()
            .oneshot(fixture.request(0, Some("wait=30000"))),
    );
    fixture.event(Event::Accepted).await;
    assert!(
        !task.is_finished(),
        "an accepted receipt alone is not terminal"
    );
    gate.release();
    let response = tokio::time::timeout(BOUND, task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["preference-applied"], "wait=30000");
    let body = body_json(response).await;
    assert_eq!(
        body["data"]["action_id"],
        fixture.service.receipt.action_id().to_string()
    );
    assert_eq!(body["data"]["status"], "succeeded");
    assert_eq!(
        body["data"]["result"],
        serde_json::json!({"value":"complete"})
    );
    assert_eq!(fixture.service.submit_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.service.cancel_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn slow_durable_admission_is_in_the_wait_budget_and_never_fabricates_acceptance() {
    let gate = Arc::new(Gate::default());
    let mut fixture = Fixture::new(
        HttpConfig::default(),
        &["browser:act", "session:read"],
        Poll::Unknown,
        Some(gate.clone()),
        None,
        None,
    );
    let mut task = tokio::spawn(
        fixture
            .app
            .clone()
            .oneshot(fixture.request(0, Some("wait=1"))),
    );
    fixture.event(Event::Submit).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut task)
            .await
            .is_err(),
        "without a durable receipt HTTP must not invent 202"
    );
    assert_eq!(fixture.service.poll_calls.load(Ordering::SeqCst), 0);
    gate.release();
    let response = tokio::time::timeout(BOUND, task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    fixture.assert_accepted(&response, Some("wait=1"));
    assert_eq!(fixture.service.submit_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.service.poll_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn legacy_service_without_acceptance_observer_does_not_claim_an_expired_wait() {
    for prefer in ["wait=0", "wait=10"] {
        let gate = Arc::new(Gate::default());
        let mut fixture = Fixture::new(
            HttpConfig::default(),
            &["browser:act", "session:read"],
            Poll::Unknown,
            Some(gate.clone()),
            None,
            None,
        );
        fixture.app = router(
            HttpConfig::default(),
            Arc::new(LegacyService(Arc::clone(&fixture.service))),
            Arc::new(Tenants(vec![
                principal(&["browser:act", "session:read"]).unwrap(),
            ])),
            Arc::new(RejectViewer),
            Arc::new(StaticReadiness(true)),
        );
        let mut task = tokio::spawn(
            fixture
                .app
                .clone()
                .oneshot(fixture.request(0, Some(prefer))),
        );
        fixture.event(Event::Submit).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut task)
                .await
                .is_err(),
            "legacy execute must supply a real receipt before any 202 response"
        );
        gate.release();
        let response = tokio::time::timeout(BOUND, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        fixture.assert_accepted(&response, None);
        let body = body_json(response).await;
        assert_eq!(
            body["data"]["action_id"],
            fixture.service.receipt.action_id().to_string()
        );
        assert_eq!(body["data"]["status"], "queued");
        assert_eq!(fixture.service.submit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.service.poll_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.service.cancel_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn accepted_callback_returns_before_the_original_submit_job_finishes() {
    for prefer in ["wait=0", "wait=5"] {
        let gate = Arc::new(Gate::default());
        let mut fixture = Fixture::new(
            HttpConfig::default(),
            &["browser:act", "session:read"],
            Poll::Queued,
            None,
            Some(gate.clone()),
            None,
        );
        let response = fixture.post(0, Some(prefer)).await;
        fixture.assert_accepted(&response, Some(prefer));
        assert!(!*gate.released.lock().unwrap());
        assert_eq!(fixture.service.submit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.service.poll_calls.load(Ordering::SeqCst), 0);
        gate.release();
        fixture.event(Event::Submitted).await;
        assert_eq!(fixture.service.cancel_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn timed_out_waiters_hold_tenant_and_global_capacity_until_submit_jobs_finish() {
    let gate = Arc::new(Gate::default());
    let mut fixture = Fixture::new(
        HttpConfig::default()
            .with_action_wait_limits(2, 1, 2, 1)
            .unwrap(),
        &["browser:act", "session:read"],
        Poll::Queued,
        None,
        Some(gate.clone()),
        None,
    );
    fixture.assert_accepted(&fixture.post(0, Some("wait=5")).await, Some("wait=5"));
    fixture.assert_accepted(&fixture.post(0, Some("wait=5")).await, None);
    fixture.assert_accepted(&fixture.post(1, Some("wait=5")).await, Some("wait=5"));
    fixture.assert_accepted(&fixture.post(2, Some("wait=5")).await, None);
    assert_eq!(fixture.service.submit_calls.load(Ordering::SeqCst), 4);
    gate.release();
    for _ in 0..4 {
        fixture.event(Event::Submitted).await;
    }
    fixture.eventually_applied(0, "wait=5").await;
    assert_eq!(fixture.service.cancel_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn dropped_submit_request_keeps_ingress_capacity_and_preserves_reserved_reads() {
    let gate = Arc::new(Gate::default());
    let mut fixture = Fixture::new(
        HttpConfig::default()
            .with_admission_limits(2, 1, 1)
            .unwrap(),
        &["browser:act", "session:read"],
        Poll::Queued,
        Some(gate.clone()),
        None,
        None,
    );
    let task = tokio::spawn(
        fixture
            .app
            .clone()
            .oneshot(fixture.request(0, Some("wait=1"))),
    );
    fixture.event(Event::Submit).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        fixture.post(0, Some("wait=0")).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(fixture.service.submit_calls.load(Ordering::SeqCst), 1);
    let read = fixture.session_read().await;
    assert_eq!(read.status(), StatusCode::NOT_FOUND);
    gate.release();
    fixture.event(Event::Submitted).await;
    fixture.eventually_applied(0, "wait=0").await;
    assert_eq!(fixture.service.cancel_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn dropped_waiter_keeps_tenant_and_global_poll_capacity_without_taking_read_slots() {
    let gate = Arc::new(Gate::default());
    let mut fixture = Fixture::new(
        HttpConfig::default()
            .with_admission_limits(1, 4, 4)
            .unwrap()
            .with_action_wait_limits(4, 4, 2, 1)
            .unwrap(),
        &["browser:act", "session:read"],
        Poll::Queued,
        None,
        None,
        Some(gate.clone()),
    );
    let task = tokio::spawn(
        fixture
            .app
            .clone()
            .oneshot(fixture.request(0, Some("wait=30000"))),
    );
    fixture.event(Event::Poll).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    fixture.assert_accepted(&fixture.post(0, Some("wait=200")).await, None);
    assert_eq!(fixture.service.poll_calls.load(Ordering::SeqCst), 1);
    fixture.assert_accepted(&fixture.post(1, Some("wait=200")).await, Some("wait=200"));
    assert_eq!(fixture.service.poll_calls.load(Ordering::SeqCst), 2);
    fixture.assert_accepted(&fixture.post(2, Some("wait=200")).await, None);
    assert_eq!(fixture.service.poll_calls.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.session_read().await.status(), StatusCode::NOT_FOUND);
    gate.release();
    fixture.event(Event::Polled).await;
    fixture.event(Event::Polled).await;
    fixture.eventually_applied(1, "wait=200").await;
    assert!(fixture.service.poll_calls.load(Ordering::SeqCst) >= 3);
    assert_eq!(fixture.service.cancel_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn wait_configuration_rejects_zero_and_above_hard_limits() {
    for limits in [
        (0, 1, 1, 1),
        (1, 0, 1, 1),
        (1, 1, 0, 1),
        (1, 1, 1, 0),
        (257, 1, 1, 1),
        (256, 33, 1, 1),
        (1, 1, 65, 1),
        (1, 1, 64, 9),
    ] {
        assert!(
            HttpConfig::default()
                .with_action_wait_limits(limits.0, limits.1, limits.2, limits.3)
                .is_err()
        );
    }
    assert!(
        HttpConfig::default()
            .with_action_wait_limits(256, 32, 64, 8)
            .is_ok()
    );
    assert!(
        HttpConfig::default()
            .with_action_wait_limits(1, 2, 1, 2)
            .is_ok(),
        "tenant caps clamp to their global limits"
    );
}
