#![allow(dead_code)]
#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use browserd_core::{PageId, SessionId, TenantId};
use browserd_viewer::{
    ControlManager, TicketPolicy, TicketRegistry, ViewerConnection, ViewerScopes,
};

pub const NOW: u64 = 10_000;
pub const ORIGIN: &str = "https://console.example.test";

pub struct ConnectedFixture {
    pub manager: ControlManager,
    pub registry: Arc<TicketRegistry>,
    pub tenant_id: TenantId,
    pub session_id: SessionId,
    pub connection: ViewerConnection,
    pub page_id: PageId,
    pub transform_epoch: u64,
}

pub fn connected_fixture(scopes: ViewerScopes) -> ConnectedFixture {
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let registry = Arc::new(TicketRegistry::new(
        TicketPolicy::new(Duration::from_secs(30), [ORIGIN])
            .expect("ticket policy should be valid"),
    ));
    let ticket = registry
        .issue(
            tenant_id.clone(),
            session_id.clone(),
            1,
            scopes,
            NOW,
            Duration::from_secs(10),
        )
        .expect("ticket should be issued");
    let connection = registry
        .consume(&ticket, &tenant_id, &session_id, 1, ORIGIN, NOW + 1)
        .expect("ticket should connect once");
    let manager = ControlManager::new(
        tenant_id.clone(),
        session_id.clone(),
        1,
        Duration::from_secs(60),
    )
    .expect("control manager should be valid");
    manager
        .attach(connection.clone())
        .expect("connection should match the manager");
    let page_id = PageId::new();
    let transform_epoch = manager
        .advance_transform(page_id.clone())
        .expect("first transform should be registered");
    ConnectedFixture {
        manager,
        registry,
        tenant_id,
        session_id,
        connection,
        page_id,
        transform_epoch,
    }
}

pub fn additional_connection(fixture: &ConnectedFixture, scopes: ViewerScopes) -> ViewerConnection {
    let ticket = fixture
        .registry
        .issue(
            fixture.tenant_id.clone(),
            fixture.session_id.clone(),
            1,
            scopes,
            NOW,
            Duration::from_secs(10),
        )
        .expect("additional ticket should be issued");
    let connection = fixture
        .registry
        .consume(
            &ticket,
            &fixture.tenant_id,
            &fixture.session_id,
            1,
            ORIGIN,
            NOW + 1,
        )
        .expect("additional ticket should connect");
    fixture
        .manager
        .attach(connection.clone())
        .expect("additional connection should attach");
    connection
}
