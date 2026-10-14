use super::{Command, GatewayActionBlockingClient, ResponsePolicy};
use crate::{
    GatewayActionCoordination, GatewayActionCoordinationError, GatewayActionSnapshot,
    GatewaySessionDirectoryRecord,
};
use browserd_core::{SessionId, TenantId};
use std::sync::mpsc::SyncSender;

pub(super) enum DirectoryCommand {
    List {
        tenant: TenantId,
        after: Option<SessionId>,
        ceiling: Option<SessionId>,
        limit: usize,
        response:
            SyncSender<Result<crate::GatewaySessionDirectoryPage, GatewayActionCoordinationError>>,
    },
    Commit {
        record: Box<GatewaySessionDirectoryRecord>,
        expected: Option<u64>,
        response: SyncSender<Result<GatewaySessionDirectoryRecord, GatewayActionCoordinationError>>,
    },
    Get {
        tenant: TenantId,
        session: SessionId,
        response: SyncSender<
            Result<Option<GatewaySessionDirectoryRecord>, GatewayActionCoordinationError>,
        >,
    },
    ByKey {
        tenant: TenantId,
        session: SessionId,
        key: String,
        response: SyncSender<Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError>>,
    },
}
impl DirectoryCommand {
    pub(super) async fn run<S: GatewayActionCoordination>(self, store: &S) {
        match self {
            Self::List {
                tenant,
                after,
                ceiling,
                limit,
                response,
            } => {
                let _ = response.send(
                    store
                        .list_single_host_directory(
                            &tenant,
                            after.as_ref(),
                            ceiling.as_ref(),
                            limit,
                        )
                        .await,
                );
            }
            Self::Commit {
                record,
                expected,
                response,
            } => {
                let _ = response.send(store.commit_single_host_directory(*record, expected).await);
            }
            Self::Get {
                tenant,
                session,
                response,
            } => {
                let _ = response.send(store.get_single_host_directory(&tenant, &session).await);
            }
            Self::ByKey {
                tenant,
                session,
                key,
                response,
            } => {
                let _ = response.send(
                    store
                        .get_action_by_idempotency(&tenant, &session, &key)
                        .await,
                );
            }
        }
    }
}
impl GatewayActionBlockingClient {
    pub fn list_single_host_directory(
        &self,
        tenant: &TenantId,
        after: Option<&SessionId>,
        ceiling: Option<&SessionId>,
        limit: usize,
    ) -> Result<crate::GatewaySessionDirectoryPage, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::SessionDirectory(Box::new(DirectoryCommand::List {
                    tenant: tenant.clone(),
                    after: after.cloned(),
                    ceiling: ceiling.cloned(),
                    limit,
                    response,
                }))
            },
            ResponsePolicy::Query,
        )
    }
    pub fn commit_single_host_directory(
        &self,
        record: GatewaySessionDirectoryRecord,
        expected: Option<u64>,
    ) -> Result<GatewaySessionDirectoryRecord, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::SessionDirectory(Box::new(DirectoryCommand::Commit {
                    record: Box::new(record),
                    expected,
                    response,
                }))
            },
            ResponsePolicy::Mutation,
        )
    }
    pub fn get_single_host_directory(
        &self,
        tenant: &TenantId,
        session: &SessionId,
    ) -> Result<Option<GatewaySessionDirectoryRecord>, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::SessionDirectory(Box::new(DirectoryCommand::Get {
                    tenant: tenant.clone(),
                    session: session.clone(),
                    response,
                }))
            },
            ResponsePolicy::Query,
        )
    }
    pub fn get_action_by_idempotency(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        key: &str,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError> {
        self.submit(
            |response| {
                Command::SessionDirectory(Box::new(DirectoryCommand::ByKey {
                    tenant: tenant.clone(),
                    session: session.clone(),
                    key: key.to_owned(),
                    response,
                }))
            },
            ResponsePolicy::Query,
        )
    }
}
