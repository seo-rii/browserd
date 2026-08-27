use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use browserd_core::{LeaseId, SessionId, TenantId};

use crate::{
    ConnectionId, TicketError, TicketPolicy, ViewerConnection, ViewerScopes, ViewerTicket,
};

#[derive(Clone)]
struct TicketRecord {
    tenant_id: TenantId,
    session_id: SessionId,
    session_incarnation: u64,
    scopes: ViewerScopes,
    expires_at_millis: u64,
    consumed: bool,
}

pub struct TicketRegistry {
    policy: TicketPolicy,
    tickets: Mutex<HashMap<ViewerTicket, TicketRecord>>,
}

impl TicketRegistry {
    #[must_use]
    pub fn new(policy: TicketPolicy) -> Self {
        Self {
            policy,
            tickets: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        session_incarnation: u64,
        scopes: ViewerScopes,
        now_millis: u64,
        ttl: Duration,
    ) -> Result<ViewerTicket, TicketError> {
        if !scopes.can_read() {
            return Err(TicketError::ReadScopeRequired);
        }
        let ttl_millis = u64::try_from(ttl.as_millis()).map_err(|_| TicketError::TtlOutOfRange)?;
        if ttl_millis == 0 || ttl_millis > self.policy.max_ttl_millis {
            return Err(TicketError::TtlOutOfRange);
        }
        let expires_at_millis = now_millis
            .checked_add(ttl_millis)
            .ok_or(TicketError::TimeOverflow)?;
        let ticket = ViewerTicket(LeaseId::new());
        self.lock_tickets()?.insert(
            ticket.clone(),
            TicketRecord {
                tenant_id,
                session_id,
                session_incarnation,
                scopes,
                expires_at_millis,
                consumed: false,
            },
        );
        Ok(ticket)
    }

    pub fn consume(
        &self,
        ticket: &ViewerTicket,
        tenant_id: &TenantId,
        session_id: &SessionId,
        session_incarnation: u64,
        origin: &str,
        now_millis: u64,
    ) -> Result<ViewerConnection, TicketError> {
        let mut tickets = self.lock_tickets()?;
        let record = tickets.get_mut(ticket).ok_or(TicketError::UnknownTicket)?;
        if &record.tenant_id != tenant_id
            || &record.session_id != session_id
            || record.session_incarnation != session_incarnation
        {
            return Err(TicketError::BindingMismatch);
        }
        if !self
            .policy
            .allowed_origins
            .iter()
            .any(|allowed| allowed == origin)
        {
            return Err(TicketError::OriginDenied);
        }
        if record.consumed {
            return Err(TicketError::AlreadyConsumed);
        }
        if now_millis >= record.expires_at_millis {
            return Err(TicketError::Expired);
        }
        record.consumed = true;
        Ok(ViewerConnection {
            id: ConnectionId(LeaseId::new()),
            tenant_id: record.tenant_id.clone(),
            session_id: record.session_id.clone(),
            session_incarnation: record.session_incarnation,
            scopes: record.scopes,
        })
    }

    pub fn discard(&self, ticket: &ViewerTicket) -> Result<bool, TicketError> {
        Ok(self.lock_tickets()?.remove(ticket).is_some())
    }

    fn lock_tickets(
        &self,
    ) -> Result<MutexGuard<'_, HashMap<ViewerTicket, TicketRecord>>, TicketError> {
        self.tickets
            .lock()
            .map_err(|_| TicketError::StateUnavailable)
    }
}
