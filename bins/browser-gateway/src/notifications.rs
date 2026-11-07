//! Independent recovery of original worker authority notification batches.
use super::*;
use browserd_core::NotificationSourceFamily;

const FAMILIES: [NotificationSourceFamily; 4] = [
    NotificationSourceFamily::ActionJournal,
    NotificationSourceFamily::SessionLifecycle,
    NotificationSourceFamily::ArtifactRegistry,
    NotificationSourceFamily::ControlJournal,
];

#[derive(Default)]
pub(super) struct NotificationRelayCursor {
    next: usize,
    sources: HashMap<(WorkerId, NotificationSourceFamily), String>,
}
struct Running<'a>(&'a AtomicBool);
impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::WorkerUnavailable,
        "worker notification recovery remains pending",
    )
}

impl<C: GatewayWorkerClient> GatewayWorkerRuntime<C> {
    /// One peer/family page per pass. Failed peers rotate too, while their source
    /// cursor remains unchanged until every imported commit is positively ACKed.
    pub fn reconcile_worker_notifications(&self, limit: usize) -> Result<usize, ApiError> {
        if !(1..=browserd_worker::MAX_NOTIFICATION_SCOPES_PER_PAGE).contains(&limit) {
            return Err(ApiError::invalid_request(
                "invalid worker notification page size",
            ));
        }
        if self
            .notification_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(0);
        }
        let _running = Running(&self.notification_running);
        let outbox = self.outbox.as_ref().ok_or_else(unavailable)?;
        let (worker_id, family, cursor) = {
            let mut scan = self.notification_scan.lock().map_err(|_| unavailable())?;
            let index = scan.next;
            scan.next = (scan.next + 1) % (self.notification_worker_count() * FAMILIES.len());
            let worker = self.notification_worker_id(index / FAMILIES.len())?;
            let family = FAMILIES[index % FAMILIES.len()];
            let cursor = scan.sources.get(&(worker.clone(), family)).cloned();
            (worker, family, cursor)
        };
        let serving = self.historical_worker(&worker_id)?;
        let page = match serving
            .client
            .request(WorkerRpcRequest::PendingNotifications {
                expected_worker_id: worker_id.clone(),
                expected_worker_epoch: serving.epoch,
                family,
                cursor: cursor.clone(),
                limit,
            })
            .map_err(worker_api_error)?
        {
            WorkerRpcResponse::Notifications {
                worker_id: observed,
                worker_epoch,
                page,
            } if observed == worker_id && worker_epoch == serving.epoch => page,
            WorkerRpcResponse::Failure(failure) => {
                return Err(worker_api_error(WorkerRpcError::Remote(failure)));
            }
            _ => return Err(unavailable()),
        };
        page.validate(&worker_id, serving.epoch, family, limit)
            .map_err(|_| unavailable())?;
        if !page.is_complete && page.cursor == cursor {
            return Err(unavailable());
        }
        let mut imported = 0;
        for commit in &page.commits {
            let expected = commit.ack();
            let ack = outbox
                .append_notification_commit(commit.clone(), Utc::now())
                .map_err(|_| unavailable())?;
            if ack != expected {
                return Err(unavailable());
            }
            match serving
                .client
                .request(WorkerRpcRequest::AckNotification {
                    expected_worker_id: worker_id.clone(),
                    expected_worker_epoch: serving.epoch,
                    ack: Box::new(ack),
                })
                .map_err(worker_api_error)?
            {
                WorkerRpcResponse::NotificationAck {
                    worker_id: observed,
                    worker_epoch,
                    ack,
                } if observed == worker_id && worker_epoch == serving.epoch && *ack == expected => {
                    imported += 1
                }
                WorkerRpcResponse::Failure(failure) => {
                    return Err(worker_api_error(WorkerRpcError::Remote(failure)));
                }
                _ => return Err(unavailable()),
            }
        }
        let mut scan = self.notification_scan.lock().map_err(|_| unavailable())?;
        let key = (worker_id, family);
        if page.is_complete {
            scan.sources.remove(&key);
        } else if let Some(cursor) = page.cursor {
            scan.sources.insert(key, cursor);
        }
        Ok(imported)
    }
}
