use browserd_coordination::{
    EventActionState, EventApprovalDecision, EventArtifactState, EventControlState, EventCursor,
    EventDownloadState, EventNotificationKind, EventNotificationResource, EventOperationState,
    EventOutbox, EventOutboxError, EventSessionExecutionState, EventSessionLifecycleState,
    EventStateSummary, OutboxAggregate, OutboxAppend, OutboxEventKind, OutboxEventWire,
    encode_outbox_event,
};
use browserd_core::{ActionId, ApprovalId, ArtifactId, OperationId, SessionId, TenantId};
use chrono::{DateTime, Utc};

pub async fn all_kinds(store: &dyn EventOutbox, tenant: &TenantId, now: DateTime<Utc>) {
    let session = SessionId::new();
    let action = ActionId::new();
    let approval = ApprovalId::new();
    let artifact = ArtifactId::new();
    let operation = OperationId::new();
    let session_aggregate = OutboxAggregate::Session {
        session_id: session.clone(),
    };
    let action_aggregate = OutboxAggregate::Action {
        session_id: session.clone(),
        action_id: action.clone(),
    };
    let artifact_aggregate = OutboxAggregate::Artifact {
        session_id: session.clone(),
        artifact_id: artifact,
    };
    let cases = [
        (
            OutboxEventKind::OperationStateChanged,
            OutboxAggregate::Operation {
                operation_id: operation,
            },
            0,
            EventStateSummary::Operation {
                state: EventOperationState::Accepted,
            },
            EventNotificationKind::OperationStateChanged,
        ),
        (
            OutboxEventKind::SessionLifecycleChanged,
            session_aggregate.clone(),
            1,
            EventStateSummary::SessionLifecycle {
                state: EventSessionLifecycleState::Ready,
            },
            EventNotificationKind::SessionLifecycleChanged,
        ),
        (
            OutboxEventKind::SessionExecutionChanged,
            session_aggregate.clone(),
            2,
            EventStateSummary::SessionExecution {
                state: EventSessionExecutionState::ReconciliationRequired,
                action_id: Some(action.clone()),
            },
            EventNotificationKind::SessionExecutionChanged,
        ),
        (
            OutboxEventKind::ActionStateChanged,
            action_aggregate.clone(),
            3,
            EventStateSummary::Action {
                state: EventActionState::OutcomeUnknown,
                resolution: None,
            },
            EventNotificationKind::ActionStateChanged,
        ),
        (
            OutboxEventKind::ActionApprovalRequired,
            action_aggregate,
            4,
            EventStateSummary::ApprovalRequired {
                approval_id: approval.clone(),
            },
            EventNotificationKind::ActionApprovalRequired,
        ),
        (
            OutboxEventKind::ApprovalDecided,
            OutboxAggregate::Approval {
                session_id: session.clone(),
                action_id: action,
                approval_id: approval,
            },
            5,
            EventStateSummary::Approval {
                state: EventApprovalDecision::Denied,
            },
            EventNotificationKind::ApprovalDecided,
        ),
        (
            OutboxEventKind::BrowserControlChanged,
            session_aggregate,
            6,
            EventStateSummary::Control {
                state: EventControlState::Human,
            },
            EventNotificationKind::BrowserControlChanged,
        ),
        (
            OutboxEventKind::DownloadCompleted,
            artifact_aggregate.clone(),
            7,
            EventStateSummary::Download {
                state: EventDownloadState::Completed,
            },
            EventNotificationKind::DownloadCompleted,
        ),
        (
            OutboxEventKind::ArtifactStateChanged,
            artifact_aggregate,
            8,
            EventStateSummary::Artifact {
                state: EventArtifactState::Available,
            },
            EventNotificationKind::ArtifactStateChanged,
        ),
    ];
    for (index, (kind, aggregate, revision, summary, public_kind)) in cases.into_iter().enumerate()
    {
        let append =
            OutboxAppend::state_changed(tenant.clone(), aggregate, revision, kind, summary.clone())
                .expect("typed descriptor");
        let event = store.append(append.clone(), now).await.expect("append");
        assert_eq!(event.cursor().position(), index as u64 + 1);
        assert_eq!(event.summary(), Some(&summary));
        assert_eq!(event.public_wire().kind, public_kind);
        let bytes = encode_outbox_event(&event).expect("safe shared body");
        let wire: OutboxEventWire = serde_json::from_slice(&bytes).expect("wire roundtrip");
        assert_eq!(wire, event.public_wire());
        match &wire.resource {
            EventNotificationResource::Action(id) => {
                assert_eq!(wire.session_id.as_ref(), Some(&session));
                assert_eq!(
                    format!(
                        "/v1/sessions/{}/actions/{id}",
                        wire.session_id.as_ref().expect("parent")
                    ),
                    format!("/v1/sessions/{session}/actions/{id}")
                );
            }
            EventNotificationResource::Artifact(id) => {
                assert_eq!(wire.session_id.as_ref(), Some(&session));
                assert_eq!(
                    format!(
                        "/v1/sessions/{}/artifacts/{id}",
                        wire.session_id.as_ref().expect("parent")
                    ),
                    format!("/v1/sessions/{session}/artifacts/{id}")
                );
            }
            EventNotificationResource::Approval(_) => {
                assert_eq!(wire.session_id.as_ref(), Some(&session))
            }
            EventNotificationResource::Operation(_) | EventNotificationResource::Session(_) => {
                assert!(wire.session_id.is_none())
            }
        }
        assert_eq!(
            bytes,
            serde_json::to_vec(&wire).expect("same polling bytes")
        );
        assert_eq!(store.append(append, now).await.expect("replay"), event);
    }
    let legacy = store
        .append(
            OutboxAppend::session_lost(tenant.clone(), session.clone(), 9),
            now,
        )
        .await
        .expect("legacy append");
    assert!(legacy.summary().is_none());
    let wire: serde_json::Value =
        serde_json::from_slice(&encode_outbox_event(&legacy).expect("legacy wire")).expect("json");
    assert_eq!(wire["kind"], "session.lifecycle_changed");
    assert!(wire.get("summary").is_none());
    let conflict = OutboxAppend::state_changed(
        tenant.clone(),
        OutboxAggregate::Session {
            session_id: session,
        },
        1,
        OutboxEventKind::SessionLifecycleChanged,
        EventStateSummary::SessionLifecycle {
            state: EventSessionLifecycleState::Failed,
        },
    )
    .expect("valid different state");
    assert_eq!(
        store.append(conflict, now).await,
        Err(EventOutboxError::ConflictingEvent)
    );
    let page = store
        .read_from(tenant, EventCursor::start(), 20, now)
        .await
        .expect("read all");
    assert_eq!(page.events().len(), 10);
    assert_eq!(
        page.events()[1].summary(),
        Some(&EventStateSummary::SessionLifecycle {
            state: EventSessionLifecycleState::Ready
        })
    );
    assert!(
        store
            .read_from(&TenantId::new(), EventCursor::start(), 20, now)
            .await
            .expect("isolated tenant")
            .events()
            .is_empty()
    );
}
