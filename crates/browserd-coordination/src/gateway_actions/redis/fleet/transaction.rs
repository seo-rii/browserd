//! Bounded optimistic transactions. Redis compares the namespace revision before any write.
//! JSON values containing u64 remain opaque strings inside Lua, avoiding numeric rounding.
use super::*;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FleetTotals {
    pub records: u64,
    pub queued: u64,
    pub live: u64,
    pub queued_tenants: u64,
    pub resources: [u64; 6],
    pub sequence: u64,
    pub authority_revision: u64,
    pub tenant_cursor: Option<TenantId>,
    pub worker_cursor: usize,
    pub active_tenant: Option<TenantId>,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TenantTotals {
    pub records: u64,
    pub queued: u64,
    pub live: u64,
    pub resources: [u64; 6],
    pub deficit: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerRow {
    pub observation: GatewayFleetWorkerObservation,
    pub expires: u64,
    // All unacknowledged shadow debits, including Reserved without a worker nonce.
    pub shadow: [u64; 6],
}
#[derive(Serialize)]
struct IndexEdit {
    key: String,
    member: String,
    add: bool,
}
#[derive(Serialize)]
struct AuthorityEdit {
    key: String,
    reference: String,
    worker_field: String,
    worker_identity: String,
    placement: String,
    status: String,
    expires: String,
    session_key: String,
}

pub(super) struct FleetTransaction<'a> {
    pub store: &'a RedisGatewayActionStore,
    pub now: u64,
    pub revision: u64,
    rows: BTreeMap<String, Option<String>>,
    writes: BTreeMap<String, Option<String>>,
    indices: Vec<IndexEdit>,
    authorities: Vec<AuthorityEdit>,
    pub deadline: Option<u64>,
}

const PREFIX: &str = r#"
local function valid_hash(key)
 return redis.call('TYPE',key)['ok']=='hash' and redis.call('PTTL',key)==-1
end
if not valid_hash(KEYS[1]) or redis.call('HGET',KEYS[1],'version')~='5' or redis.call('HGET',KEYS[1],'state')~='ready' or redis.call('HGET',KEYS[1],'fleet_digest')~=ARGV[1] or not valid_hash(KEYS[2]) then return {'invalid'} end
local revision=redis.call('HGET',KEYS[2],'revision')
if not revision then return {'invalid'} end
if ARGV[2]~='' and revision~=ARGV[2] then return {'changed'} end
local clock=redis.call('TIME')
local now=tonumber(clock[1])*1000+math.floor(tonumber(clock[2])/1000)
local floor=tonumber(redis.call('HGET',KEYS[1],'clock_floor') or '0')
if not floor or floor<0 or floor>9007199254740991 then return {'invalid'} end
now=math.max(now,floor)
redis.call('HSET',KEYS[1],'clock_floor',string.format('%.0f',now))
"#;

impl<'a> FleetTransaction<'a> {
    pub async fn begin(
        store: &'a RedisGatewayActionStore,
    ) -> Result<Self, GatewayActionCoordinationError> {
        let mut txn = Self {
            store,
            now: 0,
            revision: 0,
            rows: BTreeMap::new(),
            writes: BTreeMap::new(),
            indices: Vec::new(),
            authorities: Vec::new(),
            deadline: None,
        };
        txn.read_rows(&["totals".to_owned()], true).await?;
        Ok(txn)
    }
    async fn run(
        &self,
        tail: &str,
        args: Vec<String>,
        first: bool,
        extra_key: Option<String>,
    ) -> Result<Vec<String>, GatewayActionCoordinationError> {
        let marker = self.store.recovery_format_key();
        let state = self.store.fleet_state_key();
        let digest = encode(&self.store.fleet_config()?.digest())?;
        let revision = if first {
            String::new()
        } else {
            self.revision.to_string()
        };
        let script = format!("{PREFIX}{tail}");
        let response: Vec<String> = self
            .store
            .execute(move |mut connection| async move {
                let script = Script::new(&script);
                let mut invocation = script.prepare_invoke();
                invocation.key(marker).key(state);
                if let Some(key) = extra_key {
                    invocation.key(key);
                }
                invocation
                    .arg(digest)
                    .arg(revision)
                    .arg(args)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match response.first().map(String::as_str) {
            Some("changed") => Err(GatewayActionCoordinationError::AdmissionRevisionMismatch),
            Some("expired") => Err(GatewayActionCoordinationError::SessionAuthorityUnavailable),
            Some("invalid") | None => Err(GatewayActionCoordinationError::InvalidRedisResponse),
            _ => Ok(response),
        }
    }
    pub async fn read_rows(
        &mut self,
        fields: &[String],
        first: bool,
    ) -> Result<(), GatewayActionCoordinationError> {
        if fields.len() > 256 {
            return Err(GatewayActionCoordinationError::InvalidSessionAdmission);
        }
        let response = self
            .run(
                r#"
local result={revision,string.format('%.0f',now)}
for index=3,#ARGV do result[#result+1]=redis.call('HGET',KEYS[2],ARGV[index]) or '' end
return result
"#,
                fields.to_vec(),
                first,
                None,
            )
            .await?;
        if response.len() != fields.len() + 2 {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        self.revision = response[0]
            .parse()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        self.now = response[1]
            .parse()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        for (field, raw) in fields.iter().zip(response.into_iter().skip(2)) {
            self.rows
                .insert(field.clone(), if raw.is_empty() { None } else { Some(raw) });
        }
        Ok(())
    }
    pub fn row<T: DeserializeOwned>(
        &self,
        field: &str,
    ) -> Result<Option<T>, GatewayActionCoordinationError> {
        self.writes
            .get(field)
            .or_else(|| self.rows.get(field))
            .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?
            .as_deref()
            .map(decode)
            .transpose()
    }
    pub fn put<T: Serialize>(
        &mut self,
        field: String,
        row: &T,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.writes.insert(field, Some(encode(row)?));
        Ok(())
    }
    pub fn remove(&mut self, field: String) {
        self.writes.insert(field, None);
    }
    pub fn index(&mut self, name: &str, member: String, add: bool) {
        self.indices.push(IndexEdit {
            key: self.store.fleet_index(name),
            member,
            add,
        });
    }
    pub async fn range(
        &self,
        name: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, GatewayActionCoordinationError> {
        let lower = after.map_or_else(|| "-".to_owned(), |value| format!("({value}"));
        let result=self.run(r#"
local kind=redis.call('TYPE',KEYS[3])['ok']
if kind~='none' and (kind~='zset' or redis.call('PTTL',KEYS[3])~=-1) then return {'invalid'} end
local rows=redis.call('ZRANGEBYLEX',KEYS[3],ARGV[3],'+','LIMIT',0,ARGV[4])
for _,row in ipairs(rows) do if redis.call('ZSCORE',KEYS[3],row)~='0' then return {'invalid'} end end
local result={'ok'};for _,row in ipairs(rows) do result[#result+1]=row end;return result
"#,vec![lower,limit.to_string()],false,Some(self.store.fleet_index(name))).await?;
        if result.first().map(String::as_str) != Some("ok") || result.len() > limit + 1 {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        Ok(result.into_iter().skip(1).collect())
    }
    pub fn authority(
        &mut self,
        authority: &GatewaySessionPlacementAuthority,
        initialize_session: bool,
    ) -> Result<(), GatewayActionCoordinationError> {
        let key = authority.entry().key();
        let placement = GatewayActionPlacement::new(
            authority.authority().directory_fence().clone(),
            authority.authority().authority_revision(),
        )?;
        self.authorities.push(AuthorityEdit {
            key: self
                .store
                .fleet_authority_key(key.tenant_id(), key.session_id()),
            reference: encode(authority.authority())?,
            worker_field: worker_identity_field(
                authority.authority().directory_fence().worker_id(),
            ),
            worker_identity: encode(&GatewayFleetWorkerIdentity::new(
                authority.authority().directory_fence().worker_id().clone(),
                authority.authority().directory_fence().worker_epoch(),
                authority.authority().worker_boot_id().clone(),
            )?)?,
            placement: RedisGatewayActionStore::serialize_placement(&placement)?,
            status: if authority.status() == GatewaySessionPlacementStatus::Ready {
                "ready"
            } else {
                "closed"
            }
            .to_owned(),
            expires: authority.expires_at_millis().to_string(),
            session_key: if initialize_session {
                self.store.keys(key.tenant_id(), key.session_id()).session
            } else {
                String::new()
            },
        });
        Ok(())
    }
    pub async fn commit(self) -> Result<(), GatewayActionCoordinationError> {
        let next = increment(self.revision)?.to_string();
        let writes: Vec<_> = self
            .writes
            .iter()
            .map(|(key, value)| (key, value.as_deref().unwrap_or("")))
            .collect();
        let response=self.run(r#"
if ARGV[4]~='' and now>=tonumber(ARGV[4]) then return {'expired'} end
local writes=cjson.decode(ARGV[5]);local indices=cjson.decode(ARGV[6]);local authorities=cjson.decode(ARGV[7])
for _,edit in ipairs(indices) do
 local kind=redis.call('TYPE',edit.key)['ok']
 if kind~='none' and (kind~='zset' or redis.call('PTTL',edit.key)~=-1) then return {'invalid'} end
 local score=redis.call('ZSCORE',edit.key,edit.member)
 if score and score~='0' then return {'invalid'} end
end
for _,edit in ipairs(authorities) do
 local kind=redis.call('TYPE',edit.key)['ok']
 if kind~='none' and (kind~='hash' or redis.call('PTTL',edit.key)~=-1) then return {'invalid'} end
 if edit.session_key~='' then
  local session_kind=redis.call('TYPE',edit.session_key)['ok']
  if session_kind~='none' and (session_kind~='hash' or redis.call('PTTL',edit.session_key)~=-1 or redis.call('HGET',edit.session_key,'placement')~=edit.placement or not redis.call('HGET',edit.session_key,'last_action_sequence') or redis.call('HGET',edit.session_key,'loss_id')) then return {'invalid'} end
 end
end
for _,edit in ipairs(writes) do if edit[2]=='' then redis.call('HDEL',KEYS[2],edit[1]) else redis.call('HSET',KEYS[2],edit[1],edit[2]) end end
for _,edit in ipairs(indices) do if edit.add then redis.call('ZADD',edit.key,0,edit.member) else redis.call('ZREM',edit.key,edit.member) end end
for _,edit in ipairs(authorities) do
 redis.call('HSET',edit.key,'reference',edit.reference,'worker_field',edit.worker_field,'worker_identity',edit.worker_identity,'placement',edit.placement,'status',edit.status,'expires',edit.expires)
 if edit.session_key~='' and redis.call('EXISTS',edit.session_key)==0 then redis.call('HSET',edit.session_key,'placement',edit.placement,'last_action_sequence','0') end
end
redis.call('HSET',KEYS[2],'revision',ARGV[3]);return {'ok'}
"#,vec![next,self.deadline.map(|v|v.to_string()).unwrap_or_default(),encode(&writes)?,encode(&self.indices)?,encode(&self.authorities)?],false,None).await?;
        if response.as_slice() == ["ok"] {
            Ok(())
        } else {
            Err(GatewayActionCoordinationError::InvalidRedisResponse)
        }
    }
}
