use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use browserd_core::{OperationId, TenantId};

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct QueueTime(u64);

impl QueueTime {
    #[must_use]
    pub const fn new(milliseconds: u64) -> Self {
        Self(milliseconds)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedOperation {
    operation_id: OperationId,
    tenant_id: TenantId,
    cost: u32,
    deadline: QueueTime,
}

impl QueuedOperation {
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        tenant_id: TenantId,
        cost: u32,
        deadline: QueueTime,
    ) -> Self {
        Self {
            operation_id,
            tenant_id,
            cost,
            deadline,
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
}

#[derive(Debug)]
#[must_use = "a queue claim must be completed or explicitly requeued"]
pub struct QueueClaim {
    operation: QueuedOperation,
    generation: u64,
}

impl QueueClaim {
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        self.operation.operation_id()
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.operation.tenant_id()
    }

    #[must_use]
    pub const fn operation(&self) -> &QueuedOperation {
        &self.operation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueError {
    InvalidConfiguration,
    InvalidCost,
    InvalidWeight,
    Duplicate,
    TenantLimit,
    GlobalLimit,
    DeadlineExpired,
    NotInFlight,
}

#[derive(Debug)]
struct InFlightOwnership {
    operation: QueuedOperation,
    generation: u64,
}

#[derive(Debug)]
pub struct FairQueue {
    base_quantum: u64,
    per_tenant_limit: usize,
    global_limit: usize,
    queues: BTreeMap<TenantId, VecDeque<QueuedOperation>>,
    order: VecDeque<TenantId>,
    weights: HashMap<TenantId, u32>,
    deficits: HashMap<TenantId, u64>,
    queued_operation_ids: HashSet<OperationId>,
    in_flight: HashMap<OperationId, InFlightOwnership>,
    next_claim_generation: u64,
    expired_count: u64,
}

impl FairQueue {
    #[must_use]
    pub fn new(base_quantum: u32, per_tenant_limit: usize, global_limit: usize) -> Self {
        Self {
            base_quantum: u64::from(base_quantum),
            per_tenant_limit,
            global_limit,
            queues: BTreeMap::new(),
            order: VecDeque::new(),
            weights: HashMap::new(),
            deficits: HashMap::new(),
            queued_operation_ids: HashSet::new(),
            in_flight: HashMap::new(),
            next_claim_generation: 0,
            expired_count: 0,
        }
    }

    pub fn set_weight(&mut self, tenant_id: TenantId, weight: u32) -> Result<(), QueueError> {
        if weight == 0 {
            return Err(QueueError::InvalidWeight);
        }
        self.weights.insert(tenant_id, weight);
        Ok(())
    }

    pub fn enqueue(
        &mut self,
        operation: QueuedOperation,
        now: QueueTime,
    ) -> Result<(), QueueError> {
        if self.base_quantum == 0 || self.per_tenant_limit == 0 || self.global_limit == 0 {
            return Err(QueueError::InvalidConfiguration);
        }
        if operation.cost == 0 {
            return Err(QueueError::InvalidCost);
        }
        if operation.deadline <= now {
            return Err(QueueError::DeadlineExpired);
        }
        if self.queued_operation_ids.contains(&operation.operation_id)
            || self.in_flight.contains_key(&operation.operation_id)
        {
            return Err(QueueError::Duplicate);
        }
        if self.queued_operation_ids.len() >= self.global_limit {
            return Err(QueueError::GlobalLimit);
        }
        let tenant_id = operation.tenant_id.clone();
        let queue = self.queues.entry(tenant_id.clone()).or_default();
        if queue.len() >= self.per_tenant_limit {
            return Err(QueueError::TenantLimit);
        }
        let was_empty = queue.is_empty();
        self.queued_operation_ids
            .insert(operation.operation_id.clone());
        queue.push_back(operation);
        if was_empty {
            self.order.push_back(tenant_id.clone());
            self.deficits.entry(tenant_id).or_insert(0);
        }
        Ok(())
    }

    pub fn cancel(&mut self, operation_id: &OperationId) -> bool {
        if !self.queued_operation_ids.contains(operation_id) {
            return false;
        }
        let mut emptied = None;
        let mut removed = false;
        for (tenant_id, queue) in &mut self.queues {
            if let Some(index) = queue
                .iter()
                .position(|operation| &operation.operation_id == operation_id)
            {
                queue.remove(index);
                removed = true;
                if queue.is_empty() {
                    emptied = Some(tenant_id.clone());
                }
                break;
            }
        }
        if !removed {
            debug_assert!(false, "queued operation must exist in its tenant queue");
            return false;
        }
        self.queued_operation_ids.remove(operation_id);
        if let Some(tenant_id) = emptied {
            self.order.retain(|candidate| candidate != &tenant_id);
            self.deficits.remove(&tenant_id);
        }
        true
    }

    pub fn dequeue(&mut self, now: QueueTime) -> Option<QueueClaim> {
        let tenant_ids = self.queues.keys().cloned().collect::<Vec<_>>();
        for tenant_id in tenant_ids {
            let Some(queue) = self.queues.get_mut(&tenant_id) else {
                continue;
            };
            let mut retained = VecDeque::with_capacity(queue.len());
            while let Some(operation) = queue.pop_front() {
                if operation.deadline <= now {
                    self.queued_operation_ids.remove(&operation.operation_id);
                    self.expired_count = self.expired_count.saturating_add(1);
                } else {
                    retained.push_back(operation);
                }
            }
            *queue = retained;
            if queue.is_empty() {
                self.order.retain(|candidate| candidate != &tenant_id);
                self.deficits.remove(&tenant_id);
            }
        }

        let mut visits = 0usize;
        let maximum_visits = self.order.len().saturating_mul(1_000).max(1);
        while !self.order.is_empty() && visits < maximum_visits {
            visits = visits.saturating_add(1);
            let tenant_id = self.order.front()?.clone();
            let weight = u64::from(*self.weights.get(&tenant_id).unwrap_or(&1));
            let quantum = self.base_quantum.saturating_mul(weight);
            let deficit = self.deficits.entry(tenant_id.clone()).or_insert(0);
            let Some(queue) = self.queues.get_mut(&tenant_id) else {
                self.order.pop_front();
                continue;
            };
            let Some(front_cost) = queue.front().map(|operation| u64::from(operation.cost)) else {
                self.order.pop_front();
                self.deficits.remove(&tenant_id);
                continue;
            };
            if *deficit < front_cost {
                *deficit = deficit.saturating_add(quantum);
            }
            if *deficit < front_cost {
                self.order.rotate_left(1);
                continue;
            }
            let generation = self.next_claim_generation.checked_add(1)?;
            let operation = queue.pop_front()?;
            self.next_claim_generation = generation;
            *deficit -= u64::from(operation.cost);
            let operation_id = operation.operation_id.clone();
            let was_queued = self.queued_operation_ids.remove(&operation_id);
            debug_assert!(was_queued, "dequeued operation must have queued ownership");
            let claim = QueueClaim {
                operation: operation.clone(),
                generation,
            };
            let previous = self.in_flight.insert(
                operation_id,
                InFlightOwnership {
                    operation,
                    generation,
                },
            );
            debug_assert!(previous.is_none(), "operation cannot have two owners");
            if queue.is_empty() {
                self.order.pop_front();
                self.deficits.remove(&tenant_id);
            } else {
                let next_cost = queue.front().map_or(u64::MAX, |next| u64::from(next.cost));
                if *deficit < next_cost {
                    self.order.rotate_left(1);
                }
            }
            return Some(claim);
        }
        None
    }

    pub fn complete(&mut self, claim: &QueueClaim) -> bool {
        let owns_current_generation = self
            .in_flight
            .get(claim.operation_id())
            .is_some_and(|ownership| ownership.generation == claim.generation);
        if !owns_current_generation {
            return false;
        }
        self.in_flight.remove(claim.operation_id());
        true
    }

    pub fn requeue(&mut self, claim: &QueueClaim, now: QueueTime) -> Result<(), QueueError> {
        let operation_id = claim.operation_id();
        let Some(ownership) = self.in_flight.get(operation_id) else {
            return Err(QueueError::NotInFlight);
        };
        if ownership.generation != claim.generation {
            return Err(QueueError::NotInFlight);
        }
        if ownership.operation.deadline <= now {
            self.in_flight.remove(operation_id);
            self.expired_count = self.expired_count.saturating_add(1);
            return Err(QueueError::DeadlineExpired);
        }
        if self.queued_operation_ids.len() >= self.global_limit {
            return Err(QueueError::GlobalLimit);
        }
        let tenant_id = ownership.operation.tenant_id.clone();
        let queue = self.queues.entry(tenant_id.clone()).or_default();
        if queue.len() >= self.per_tenant_limit {
            return Err(QueueError::TenantLimit);
        }
        let was_empty = queue.is_empty();
        let Some(ownership) = self.in_flight.remove(operation_id) else {
            return Err(QueueError::NotInFlight);
        };
        self.queued_operation_ids.insert(operation_id.clone());
        let deficit = self.deficits.entry(tenant_id.clone()).or_insert(0);
        *deficit = deficit.saturating_add(u64::from(ownership.operation.cost));
        queue.push_front(ownership.operation);
        if was_empty {
            self.order.push_back(tenant_id);
        }
        Ok(())
    }

    #[must_use]
    pub const fn expired_count(&self) -> u64 {
        self.expired_count
    }
}
