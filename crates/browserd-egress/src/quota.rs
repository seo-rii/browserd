use std::collections::BTreeMap;
use std::time::Duration;

/// A caller-supplied monotonic timestamp used to keep quota tests and policy
/// decisions independent of wall-clock changes.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicMillis(u64);

impl MonotonicMillis {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaLimits {
    pub max_concurrent_connections: u32,
    pub max_connection_starts_per_window: u32,
    pub max_dns_queries_per_window: u32,
    pub max_egress_bytes_per_window: u64,
    pub max_total_egress_bytes: u64,
    pub max_response_bytes: Option<u64>,
    pub accounting_window: Duration,
    pub idle_connection_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaError {
    InvalidLimits,
    ClockMovedBackwards,
    ConcurrentConnections,
    ConnectionCreationRate,
    DnsQueryRate,
    EgressBytesPerWindow,
    TotalEgressBytes,
    ResponseBytes,
    UnknownConnection,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaUsage {
    pub active_connections: u32,
    pub connection_starts_in_window: u32,
    pub dns_queries_in_window: u32,
    pub window_egress_bytes: u64,
    pub total_egress_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct ConnectionState {
    last_activity: MonotonicMillis,
    response_bytes: u64,
}

/// Session-local, bounded network quota accounting.
#[derive(Debug)]
pub struct QuotaLedger {
    limits: QuotaLimits,
    accounting_window_millis: Option<u64>,
    idle_timeout_millis: Option<u64>,
    limits_valid: bool,
    window_start: MonotonicMillis,
    last_observed: MonotonicMillis,
    connection_starts_in_window: u32,
    dns_queries_in_window: u32,
    window_egress_bytes: u64,
    total_egress_bytes: u64,
    next_connection_id: u64,
    reserved_connections: u32,
    connections: BTreeMap<ConnectionId, ConnectionState>,
}

impl QuotaLedger {
    #[must_use]
    pub fn new(limits: QuotaLimits) -> Self {
        let accounting_window_millis = {
            let millis = limits.accounting_window.as_millis();
            (millis != 0 && millis <= u128::from(u64::MAX))
                .then(|| u64::try_from(millis).ok())
                .flatten()
        };
        let idle_timeout_millis = {
            let millis = limits.idle_connection_timeout.as_millis();
            (millis != 0 && millis <= u128::from(u64::MAX))
                .then(|| u64::try_from(millis).ok())
                .flatten()
        };
        Self {
            accounting_window_millis,
            idle_timeout_millis,
            limits_valid: accounting_window_millis.is_some() && idle_timeout_millis.is_some(),
            limits,
            window_start: MonotonicMillis::new(0),
            last_observed: MonotonicMillis::new(0),
            connection_starts_in_window: 0,
            dns_queries_in_window: 0,
            window_egress_bytes: 0,
            total_egress_bytes: 0,
            next_connection_id: 1,
            reserved_connections: 0,
            connections: BTreeMap::new(),
        }
    }

    pub fn open_connection(&mut self, now: MonotonicMillis) -> Result<ConnectionId, QuotaError> {
        self.reserve_connection(now)?;
        let result = self.open_reserved_connection(now);
        if result.is_err() {
            self.cancel_connection_reservation();
        }
        result
    }

    pub(crate) fn reserve_connection(&mut self, now: MonotonicMillis) -> Result<(), QuotaError> {
        self.advance_window(now)?;
        let reserved = usize::try_from(self.reserved_connections)
            .map_err(|_| QuotaError::ArithmeticOverflow)?;
        let occupied = self
            .connections
            .len()
            .checked_add(reserved)
            .ok_or(QuotaError::ArithmeticOverflow)?;
        let maximum = usize::try_from(self.limits.max_concurrent_connections)
            .map_err(|_| QuotaError::ArithmeticOverflow)?;
        if occupied >= maximum {
            return Err(QuotaError::ConcurrentConnections);
        }
        self.reserved_connections = self
            .reserved_connections
            .checked_add(1)
            .ok_or(QuotaError::ArithmeticOverflow)?;
        Ok(())
    }

    pub(crate) fn cancel_connection_reservation(&mut self) -> bool {
        let Some(remaining) = self.reserved_connections.checked_sub(1) else {
            return false;
        };
        self.reserved_connections = remaining;
        true
    }

    pub(crate) fn open_reserved_connection(
        &mut self,
        now: MonotonicMillis,
    ) -> Result<ConnectionId, QuotaError> {
        self.advance_window(now)?;
        if self.reserved_connections == 0 {
            return Err(QuotaError::UnknownConnection);
        }
        if self.connection_starts_in_window >= self.limits.max_connection_starts_per_window {
            return Err(QuotaError::ConnectionCreationRate);
        }
        let identifier = ConnectionId(self.next_connection_id);
        let Some(next_identifier) = self.next_connection_id.checked_add(1) else {
            return Err(QuotaError::ArithmeticOverflow);
        };
        let Some(next_starts) = self.connection_starts_in_window.checked_add(1) else {
            return Err(QuotaError::ArithmeticOverflow);
        };

        self.next_connection_id = next_identifier;
        self.connection_starts_in_window = next_starts;
        self.reserved_connections -= 1;
        self.connections.insert(
            identifier,
            ConnectionState {
                last_activity: now,
                response_bytes: 0,
            },
        );
        Ok(identifier)
    }

    pub fn close_connection(&mut self, identifier: ConnectionId) -> bool {
        self.connections.remove(&identifier).is_some()
    }

    pub fn record_dns_query(&mut self, now: MonotonicMillis) -> Result<(), QuotaError> {
        self.advance_window(now)?;
        if self.dns_queries_in_window >= self.limits.max_dns_queries_per_window {
            return Err(QuotaError::DnsQueryRate);
        }
        self.dns_queries_in_window = self
            .dns_queries_in_window
            .checked_add(1)
            .ok_or(QuotaError::ArithmeticOverflow)?;
        Ok(())
    }

    pub fn record_egress(
        &mut self,
        identifier: ConnectionId,
        bytes: u64,
        now: MonotonicMillis,
    ) -> Result<(), QuotaError> {
        self.advance_window(now)?;
        let Some(connection) = self.connections.get(&identifier) else {
            return Err(QuotaError::UnknownConnection);
        };
        let window_bytes = self
            .window_egress_bytes
            .checked_add(bytes)
            .ok_or(QuotaError::ArithmeticOverflow)?;
        let total_bytes = self
            .total_egress_bytes
            .checked_add(bytes)
            .ok_or(QuotaError::ArithmeticOverflow)?;
        let response_bytes = connection
            .response_bytes
            .checked_add(bytes)
            .ok_or(QuotaError::ArithmeticOverflow)?;

        if window_bytes > self.limits.max_egress_bytes_per_window {
            return Err(QuotaError::EgressBytesPerWindow);
        }
        if total_bytes > self.limits.max_total_egress_bytes {
            return Err(QuotaError::TotalEgressBytes);
        }
        if self
            .limits
            .max_response_bytes
            .is_some_and(|maximum| response_bytes > maximum)
        {
            return Err(QuotaError::ResponseBytes);
        }

        let Some(connection) = self.connections.get_mut(&identifier) else {
            return Err(QuotaError::UnknownConnection);
        };
        connection.response_bytes = response_bytes;
        connection.last_activity = now;
        self.window_egress_bytes = window_bytes;
        self.total_egress_bytes = total_bytes;
        Ok(())
    }

    pub fn expire_idle(&mut self, now: MonotonicMillis) -> usize {
        let Some(timeout) = self.idle_timeout_millis else {
            return 0;
        };
        if now < self.last_observed {
            return 0;
        }
        self.last_observed = now;
        let before = self.connections.len();
        self.connections
            .retain(|_, connection| now.0.saturating_sub(connection.last_activity.0) < timeout);
        before.saturating_sub(self.connections.len())
    }

    #[must_use]
    pub fn usage(&self) -> QuotaUsage {
        let active_connections = u32::try_from(self.connections.len()).unwrap_or(u32::MAX);
        QuotaUsage {
            active_connections,
            connection_starts_in_window: self.connection_starts_in_window,
            dns_queries_in_window: self.dns_queries_in_window,
            window_egress_bytes: self.window_egress_bytes,
            total_egress_bytes: self.total_egress_bytes,
        }
    }

    fn advance_window(&mut self, now: MonotonicMillis) -> Result<(), QuotaError> {
        if !self.limits_valid {
            return Err(QuotaError::InvalidLimits);
        }
        let Some(window_millis) = self.accounting_window_millis else {
            return Err(QuotaError::InvalidLimits);
        };
        if now < self.last_observed {
            return Err(QuotaError::ClockMovedBackwards);
        }
        self.last_observed = now;
        if now.0.saturating_sub(self.window_start.0) >= window_millis {
            self.window_start = now;
            self.connection_starts_in_window = 0;
            self.dns_queries_in_window = 0;
            self.window_egress_bytes = 0;
        }
        Ok(())
    }
}
