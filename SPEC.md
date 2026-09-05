# browserd v1 상세 기술 스펙

> **멀티테넌트 AI 에이전트용 비즈니스급 브라우저 런타임**  
> 상태: Draft 0.3  
> 기준 아키텍처: Rust greenfield / outer-sandboxed Chromium shard + BrowserContext session / Skill-only API

---

## 0. 문서 목적

이 문서는 Cloudflare Browser Rendering과 유사한 형태의 자체 운영 브라우저 서버를 새로 구현하기 위한 v1 제품·기술 스펙이다.

기존 Steel Browser를 직접 포크해 코어를 개조하는 대신, 다음 원칙으로 새로운 Rust 서비스를 구현한다.

- **Session은 Chromium `BrowserContext`에 대응한다.**
- **BrowserShard는 하나의 Chromium 프로세스 트리와 이를 감싸는 outer OS sandbox에 대응한다.**
- 하나의 BrowserShard에는 제한된 수의 Session을 배치한다.
- 외부에는 raw CDP, Playwright, Puppeteer 연결을 제공하지 않는다.
- 모든 브라우저 조작은 서버가 정의한 **신뢰된 Skill API**로만 수행한다.
- PDF, screenshot, scrape, viewer 등은 코어와 분리된 Feature Module로 구현한다.
- 용량 제한, 공정한 스케줄링, tenant quota, browser recycle, 감사 로그, SSRF 차단을 처음부터 제품 기능으로 취급한다.
- Steel의 좋은 구현은 참고하거나 라이선스 조건을 확인한 뒤 선택적으로 포팅하되, Steel API 또는 내부 구조와의 호환은 목표로 하지 않는다.

이 문서에서 `browserd`는 프로젝트의 작업명이다.

Draft 0.2는 Draft 0.1의 제품 방향을 유지하면서 다음을 아키텍처의 필수 요소로 승격한다.

- BrowserShard별 **outer OS sandbox**와 worker-death cleanup
- netns 기반 **mandatory egress**와 session별 proxy route
- 새 target을 실행 전에 초기화하는 **TargetManager bootstrap barrier**
- action의 exactly-once를 주장하지 않는 **action ledger / `OUTCOME_UNKNOWN` 모델**
- session lifecycle, placement, execution, human control의 **독립 상태 축**
- `CreateSessionOperation`, worker reservation, SessionAdmission/ActionAdmission 분리
- viewer control fencing, CJK IME, artifact state machine, multi-node fencing
- Chromium binary와 CDP schema를 하나로 묶는 immutable compatibility artifact

Draft 0.3은 Draft 0.2에 대한 설계 검토를 반영해 다음을 추가·수정한다.

- `RECONCILIATION_REQUIRED`/`OUTCOME_UNKNOWN` 해소를 위한 명시적 **resolve API**(§15.11)
- **Approval API**(§24.4)와 at-least-once **event 전달 채널**(§15.12)
- worker loss 후 action 터미널 상태의 gateway-side **derivation rule**(§21.3, §28.4, D-33)
- **Supervisor Lease / Directory Lease** 분리, TTL ordering, `worker_epoch` 내구성(§13.4, §28.1, §28.2, D-32)
- `OUTCOME_UNKNOWN`의 HTTP 표현을 5xx 오류에서 **200 + 터미널 상태**로 변경(§25.2)
- in-shard compromise 시 egress route/과금/감사 오귀속의 명시(§3.3, §3.4, §19.1)
- HTTPS allowlist의 **CONNECT enforcement granularity 한계** 명시(§19.4, §19.6, §33.2)
- taint/crash abuse에 대한 attribution과 **isolation auto-escalation**(§13.7, D-31)
- **BFCache 비활성** 결정(D-29)과 per-context proxy quirk의 Phase -1 spike 항목화(§32)
- **Warm shard pool**(§11.8), memory 밀도 기대치(§12.3), viewer/snapshot 한도 보강(§12.4, §12.5, §16.5)
- idempotency 보존 기간(§15.9), session incarnation 고정(§8.3), node staleness predicate(§14.6), dialog 기본 정책(§14.9), `fill_secret`/`wait_for` 명세(§15.7), snapshot inline 옵션(§16.1), session list API(§15.4), PostgreSQL degraded mode(§21.6)

---

# 1. 핵심 결정

| ID | 결정 |
|---|---|
| D-01 | 코어는 Rust로 새로 구현한다. |
| D-02 | 한 Session은 하나의 non-persistent BrowserContext다. |
| D-03 | 한 BrowserShard는 하나의 Chromium 프로세스 트리와 그 outer sandbox를 포함하는 운영 단위다. |
| D-04 | `shared_context`에서는 하나의 BrowserShard에 여러 tenant의 Session을 배치할 수 있다. 동일 shard의 browser-process compromise 위험은 공유한다. |
| D-05 | raw CDP/Playwright/Puppeteer endpoint는 v1에서 제공하지 않는다. |
| D-06 | 외부 브라우저 접근은 typed Skill API로만 허용한다. |
| D-07 | Chromium 자체 sandbox는 항상 활성화한다. `--no-sandbox`와 이를 우회하는 production fallback은 금지한다. |
| D-08 | per-session VM/container는 요구하지 않지만 **모든 production BrowserShard는 별도 user/PID/mount/network namespace와 cgroup을 갖는 outer OS sandbox를 사용한다.** |
| D-09 | Chromium netns에는 direct Internet/host route를 주지 않는다. 모든 외부 연결은 session-bound mandatory egress route를 통해서만 가능하다. |
| D-10 | Feature Module은 compile-time registry로 구성한다. 임의 native/WASM plugin 로딩은 허용하지 않는다. |
| D-11 | live BrowserContext의 다른 worker로의 무중단 migration은 v1 범위에서 제외한다. |
| D-12 | Chromium binary, CDP schema, launch/font/extension bundle을 immutable compatibility artifact로 고정하고 canary를 거쳐 교체한다. |
| D-13 | 모든 새 page/frame/worker target은 실행 전에 `TargetManager` bootstrap barrier를 통과해야 한다. 초기화 실패 target은 실행시키지 않는다. |
| D-14 | 모든 agent action, control transition, human input은 `SessionExecutor`가 순서화한다. |
| D-15 | idempotency는 exactly-once를 의미하지 않는다. dispatch 여부를 확정할 수 없는 mutating action은 `OUTCOME_UNKNOWN`이며 자동 replay하지 않는다. |
| D-16 | `QUEUED`는 live Session 상태가 아니라 `CreateSessionOperation` 상태다. |
| D-17 | `FULL`, `BUSY`는 lifecycle state가 아니라 capacity/execution에서 파생되는 상태다. |
| D-18 | Standard profile에서는 arbitrary JavaScript `evaluate`를 비활성화한다. 별도 privileged scope/profile에서만 허용한다. |
| D-19 | Shared-context shard에서는 Chrome extension을 기본적으로 허용하지 않는다. 승인 extension은 tenant-dedicated 이상에서만 사용한다. |
| D-20 | Session admission과 resource-heavy Action admission을 별도로 수행한다. |
| D-21 | Worker ownership lease가 사라지면 shard egress route를 먼저 revoke하고 outer sandbox의 cgroup 전체를 종료한다. |
| D-22 | Shared-context는 session별 CPU/RAM/disk hard isolation을 보장하지 않는다. hard containment는 shard 단위다. |
| D-23 | page-rendered secret이 screenshot/PDF/viewer에서 자동 제거된다고 보장하지 않는다. 로그/API payload secret redaction과 화면 보안은 별개다. |
| D-24 | crash/checkpoint 복원은 기본적으로 새 SessionId를 생성한다. 기존 live session identity의 투명한 부활은 v1에서 하지 않는다. |
| D-25 | shared network class에서는 tenant가 지정한 arbitrary upstream proxy를 허용하지 않는다. private/custom proxy는 별도 dedicated network class에서만 제공한다. |
| D-26 | Gateway→Worker의 모든 session RPC는 worker epoch와 placement version으로 fencing한다. |
| D-27 | 운영 중 isolation/Chromium regression 발생 시 `max_contexts_per_shard=1` 또는 `force_dedicated_process`로 즉시 축소할 수 있어야 한다. |
| D-28 | `OUTCOME_UNKNOWN`과 `RECONCILIATION_REQUIRED`의 해소는 명시적 resolve API 또는 session close로만 가능하다. resolve는 caller의 확정 기록이며 browserd가 outcome을 소급 주장하지 않는다. |
| D-29 | back/forward cache는 v1 launch profile에서 비활성화한다. 재활성화는 compatibility artifact 변경으로 취급한다. |
| D-30 | 상태 전이 알림은 at-least-once event 채널(webhook/event polling)로 제공하되, polling API가 항상 상태의 source of truth다. |
| D-31 | 반복적으로 taint/crash를 유발하는 tenant는 자동으로 더 강한 isolation profile로 escalate할 수 있다. shared-context 배치는 권리가 아니라 정책이다. |
| D-32 | Supervisor Lease와 Directory Lease를 구분하고 `supervisor_lease_ttl ≤ directory_lease_ttl`을 유지한다. |
| D-33 | Worker loss 후 non-terminal action은 gateway가 자신의 전달 상태로 derive한다. 전달 전 실패가 입증되면 `FAILED_KNOWN(not_dispatched)`, 아니면 `OUTCOME_UNKNOWN`이며 결과를 조회 가능한 mapping에 기록한다. |

# 2. 목표와 비목표

## 2.1 목표

### 제품 목표

1. AI agent가 Skill을 통해 browser session을 생성하고 조작할 수 있어야 한다.
2. 사용자는 실시간 화면을 보고 필요한 경우 직접 mouse/keyboard/IME control을 인계받을 수 있어야 한다.
3. 하나의 서버에서 다수의 BrowserContext session을 효율적으로 운영하되, browser process 단위의 failure/security blast radius를 명시적으로 제한해야 한다.
4. tenant별 concurrency, queue, TTL, artifact, bandwidth, network, isolation 정책을 적용할 수 있어야 한다.
5. PDF, screenshot, scrape, upload/download 등의 기능을 resource admission이 적용되는 확장 가능한 방식으로 제공해야 한다.
6. 브라우저 crash, memory leak, target leak, 장시간 실행에 대응해 shard를 자동 drain/recycle해야 한다.
7. Chromium이 내부망, metadata endpoint, host localhost 서비스에 direct 접근할 수 없어야 한다.
8. single-node로 시작할 수 있으면서 추후 gateway/worker 다중 노드로 확장 가능해야 한다.
9. action timeout, worker crash, gateway retry가 외부 side effect의 자동 중복 실행으로 이어지지 않아야 한다.
10. shared-context 안전성이 불확실할 때 운영 설정만으로 dedicated-process 모드로 축소할 수 있어야 한다.

### 기술 목표

- warm shard에서 context 생성 p95 목표: **500 ms 이하**
- cold Chromium 기동 포함 session 생성 p95 목표: **3초 이하**
- browserd 자체 synchronous action dispatch overhead p95 목표: **50 ms 이하**
- viewer end-to-end frame latency p95 목표: **300 ms 이하**
- session 간 cookie/storage/artifact 귀속 혼선: **0건**
- bootstrap 전에 실행된 unmanaged target: **0건**
- Chromium의 mandatory egress 경로 외 direct outbound 성공: **0건**
- one-shard Chromium crash의 최대 browser blast radius: 해당 shard의 session 수 이하
- worker 사망 후 ownership lease expiry 내 orphan Chromium/egress route: **0개**
- mutating action outcome이 불확실한 장애에서 자동 replay: **0건**
- rolling deployment은 **spare capacity와 호환 worker가 존재하는 환경**에서 새 session admission 중단 없이 drain 가능

위 수치는 초기 성능 목표다. 실제 production 기본값은 benchmark/soak/security gate를 통과한 뒤 확정한다.

## 2.2 비목표

v1에서는 다음을 제공하거나 보장하지 않는다.

- public raw CDP endpoint
- Playwright/Puppeteer/Selenium 호환 서버
- Playwright locator/actionability semantics의 완전한 재현
- tenant가 업로드한 임의 Chrome extension 설치
- tenant가 업로드한 native/WASM plugin 실행
- per-session kernel/VM 수준 hard isolation
- 동일 `shared_context` shard 내부에서 browser-process compromise 후 tenant 간 보안 격리
- shared-context에서 session별 CPU/RAM/disk hard limit
- 외부 웹사이트 side effect에 대한 exactly-once action execution
- page가 렌더링한 secret의 screenshot/PDF/viewer 자동 비노출 보장
- full Chrome profile의 완전한 suspend/resume
- live BrowserContext의 다른 worker로의 migration
- crash 후 동일 SessionId의 투명한 부활
- IndexedDB/service worker/cache까지 포함한 완전한 browser state checkpoint
- CAPTCHA solving
- stealth/anti-bot 우회 보장
- audio/video 미디어 스트리밍
- 사용자 바이너리 실행 또는 shell 제공
- Firefox/WebKit 지원

# 3. 위협 모델과 신뢰 경계

## 3.1 신뢰하는 구성요소

- browser gateway/worker/sandbox supervisor 바이너리
- 배포된 Feature Module 코드
- 인증 서비스와 tenant policy store
- artifact store와 secret store
- mandatory egress proxy
- agent server의 Skill 실행 코드
- 운영자가 고정한 Chromium/launch/font/certificate artifact

Feature Module과 worker 코드는 trusted code이지만 **실수 가능성**은 가정한다. 따라서 Feature에도 raw filesystem/network/CDP 권한을 무제한 제공하지 않고 내부 capability wrapper를 사용한다.

## 3.2 신뢰하지 않는 입력

- tenant가 보낸 API 입력
- 사용자의 자연어 요청
- LLM이 생성한 action argument
- 방문한 웹사이트와 웹사이트 JavaScript
- Chromium/CDP에서 도착한 비정상·과대 event/payload
- 다운로드 파일
- 업로드 파일명과 MIME 정보
- viewer client가 보내는 frame ack/input/IME event
- redirect, DNS 응답, upstream proxy 응답
- stale/replayed capability 또는 viewer token

`Skill-only`는 Skill 구현을 신뢰한다는 뜻이지 Skill argument를 신뢰한다는 뜻이 아니다. 모든 argument는 schema, quota, authorization, policy validation을 통과해야 한다.

## 3.3 보장 수준

| 영역 | v1 보장 수준 |
|---|---|
| API tenant/session authorization | 강한 보장 |
| Artifact tenant/session namespace | 강한 보장 |
| Chromium direct external/host network 차단 | 강한 보장: outer netns/route/firewall invariant |
| public-web profile의 loopback/private/metadata SSRF 차단 | 강한 보장: mandatory proxy가 실제 connect 대상 IP를 검증 |
| Cookie/localStorage 등 BrowserContext storage 분리 | Chromium BrowserContext 수준의 보장 + 지속적인 회귀 테스트 |
| 같은 shared shard의 browser-process compromise 후 다른 context 보호 | 비보장 |
| compromise된 shard 내부에서 co-resident session의 egress route/quota/audit identity 오용 방지 | 비보장. shard blast radius에 포함(§19.1) |
| browser-process compromise 후 다른 shard/worker service 접근 제한 | outer shard sandbox가 제공하는 방어 경계 |
| session별 CPU/RAM/disk hard limit | 비보장. shard 단위 hard containment만 제공 |
| 동일 idempotency key의 정상 retry 중복 dispatch 방지 | 보장 가능 |
| external side effect exactly-once | 비보장 |
| action 실행 여부를 모르는 장애 처리 | `OUTCOME_UNKNOWN`, 자동 replay 금지 |
| 로그/API/trace에 secret 원문 미기록 | 강한 보장 목표 |
| 페이지가 그린 secret의 screenshot/PDF/viewer 비노출 | 비보장 |
| prompt injection으로 인한 의미론적 오작동 방지 | browserd 단독 비보장. typed action, policy/approval hook 제공 |

## 3.4 허용하는 위험

기본 `shared_context`에서는 서로 다른 tenant의 BrowserContext가 하나의 Chromium browser process를 공유한다. Chromium browser-process compromise 또는 관련 zero-day가 발생하면 동일 shard 내 다른 context에 영향을 줄 가능성을 허용한다. 이 영향에는 co-resident session의 egress route를 통한 network policy/quota/과금/감사 identity 오용이 포함된다.

이를 다음으로 제한한다.

- raw CDP와 Chromium internal ID를 외부에 제공하지 않는다.
- 모든 shard는 Chromium sandbox와 별도의 outer OS sandbox를 사용한다.
- shard별 network namespace에는 mandatory egress 외 경로가 없다.
- shard당 context/target/resource budget과 browser recycle을 적용한다.
- cleanup/target attribution이 불확실하면 shard를 taint하고 재사용하지 않는다.
- 고보안 tenant는 `tenant_dedicated_shard`, `dedicated_process`, `dedicated_worker`를 선택한다.
- taint/compromise 판정 시 해당 shard의 동시간대 usage/audit event에 diagnostic flag를 남겨 과금·감사 분쟁 처리 근거로 사용한다.

이 모델은 application-level session isolation + shard-level OS containment이며, per-session kernel/VM isolation과 동일하다고 주장하지 않는다.

## 3.5 주요 공격/장애 시나리오

| 공격/장애 | 대응 |
|---|---|
| 다른 tenant session ID 추측 | opaque ID + tenant binding + session capability |
| raw CDP로 다른 target attach | raw CDP 미제공 + internal target ownership validation |
| localhost/metadata SSRF | `<-loopback>` + mandatory proxy + shard netns + connect-target IP 검증 |
| direct UDP/QUIC/WebRTC 우회 | shard netns에서 proxy 외 route 제거 + host firewall |
| DNS rebinding | egress proxy가 resolve·IP 검사·검사한 sockaddr에 직접 connect |
| tenant upstream proxy로 SSRF 의미 우회 | shared tier arbitrary upstream proxy 금지, dedicated network class로 분리 |
| 다운로드 path traversal | artifact ID만 API에 노출, session temp namespace |
| session A artifact를 B가 조회 | tenant/session namespace + authz |
| 무한 popup/frame/worker 생성 | page/frame/worker/target count + creation-rate limit + pids.max |
| 한 session이 shard RAM/CPU를 과도하게 사용 | workload observation + shard cgroup + session eviction/escalation policy; per-session hard isolation은 비보장 |
| worker가 죽었지만 Chromium이 살아 있음 | ownership lease expiry → egress revoke → `cgroup.kill` |
| click dispatch 후 worker crash | action `OUTCOME_UNKNOWN`, 재시도 금지 |
| timeout action이 뒤늦게 실행 | quiescence barrier 전 다음 mutating action 금지 |
| viewer stale input/replay | control lease epoch + input sequence + transform epoch |
| approval 후 DOM/navigation 변경 | canonical action proposal hash + origin/document/session incarnation binding |
| secret이 로그에 노출 | secret reference + structured redaction + audit payload policy |
| secret이 screenshot에 노출 | 보장하지 않음; viewer/screenshot/PDF를 sensitive capability로 취급 |
| 악성/대형 다운로드 | streaming size limit + quarantine/scanner hook + artifact admission |
| Feature post-hook 실패 | browser effect와 feature/audit outcome을 분리, 필요 시 session/shard degrade |

# 4. 용어

| 용어 | 정의 |
|---|---|
| Tenant | 과금·quota·policy의 최상위 고객 단위 |
| Principal | 실제 호출 주체. 사용자, agent, service account 등 |
| CreateSessionOperation | Session admission/placement/context 생성의 비동기 작업. `QUEUED`는 이 객체의 상태다. |
| Session | 하나의 BrowserContext와 그 page/frame/target registry, executor, artifact namespace의 논리 단위 |
| Session Incarnation | 동일 live Session identity 내부의 생성 세대를 나타내는 fencing 값. v1 crash restore는 새 SessionId가 기본이다. |
| BrowserShard | 하나의 Chromium 프로세스 트리 + outer OS sandbox + cgroup + target registry의 운영/failure 단위 |
| Shard Sandbox | user/PID/mount/network namespace, private fs/shm, cgroup으로 구성된 Chromium 외부 격리 |
| Worker | 하나의 호스트에서 여러 BrowserShard를 소유·감독하는 프로세스 |
| Sandbox Supervisor | worker와 독립적인 lifecycle/cleanup 권한으로 shard sandbox를 생성·종료하는 최소 supervisor |
| Gateway | 인증, 전역 quota, operation/idempotency, session routing, regional queue를 담당하는 API 계층 |
| Page | BrowserContext 내 top-level page/tab의 논리 객체 |
| Target | Chromium CDP target. page, OOPIF, worker, service worker 등을 포함 |
| TargetManager | 새 target을 pause-before-run 상태에서 ownership/limit/emulation/hook 설정 후 실행시키는 관리자 |
| SessionExecutor | agent action, human control, input, close를 session 단위로 순서화하는 executor |
| Action | navigate, click, type, screenshot 등 하나의 요청 가능한 Skill 작업 |
| Action Ledger | ActionId별 dispatch/outcome 상태를 추적하는 기록 |
| Artifact | screenshot, PDF, download, upload, checkpoint 등의 저장 객체 |
| Feature Module | PDF, scrape, viewer 등 서버측 compile-time 기능 모듈 |
| Isolation Profile | session을 shard/worker에 배치하는 security/reuse 정책 |
| Network Class | public, private, custom proxy 등 egress topology/policy 등급 |
| Control Lease | agent 또는 human input 권한의 fencing 가능한 임대 상태 |
| Placement | Session이 소유되는 worker/shard와 worker epoch/placement version 정보 |
| Reservation | Worker capacity를 짧은 TTL 동안 선점하는 admission token |
| SessionAdmission | context/shard/process baseline resource를 할당하는 admission |
| ActionAdmission | PDF/screenshot/artifact 등 burst resource를 쓰는 action의 실행 admission |
| Compatibility Artifact | Chromium binary + CDP schema + launch/font/extension 등 process-level 호환 identity |
| Taint | cleanup/protocol/security 상태를 신뢰할 수 없어 shard 재사용을 금지하는 상태 |
| Supervisor Lease | worker↔Sandbox Supervisor 간 host-local shard ownership lease. 만료 시 supervisor가 egress revoke 후 shard kill을 수행한다(§13.4) |
| Directory Lease | worker↔session directory(coordination store) 간 전역 ownership lease. gateway routing/fencing의 기준이다(§28.2) |
| Reconciliation | `OUTCOME_UNKNOWN` action의 semantic outcome을 caller가 명시적으로 확정 기록하는 절차(§15.11) |
| Warm Pool | CompatibilityKey별로 미리 기동해 두는 spare shard 집합(§11.8) |

# 5. 아키텍처 원칙

1. **Capability-first**  
   tenant와 session은 URL parameter만으로 접근할 수 없다. 모든 작업은 tenant/session/incarnation scope가 포함된 capability 또는 서버 내부 actor identity를 요구한다.

2. **No raw browser handles**  
   외부 API와 Feature Module에는 Browser, BrowserContext, raw CDP transport, Target ID를 그대로 반환하지 않는다.

3. **Context는 application session, sandboxed process는 failure/security containment unit**  
   BrowserContext storage 격리와 Chromium process/OS containment를 동일한 보안 경계로 혼동하지 않는다.

4. **Pause before trust**  
   새 target은 browserd가 ownership, resource limit, emulation/network hook을 적용하기 전에 실행될 수 없다.

5. **Limits are core**  
   quota와 limit은 middleware가 아니라 scheduler, SessionExecutor, TargetManager, ArtifactManager의 state machine 일부다.

6. **Artifacts are references**  
   큰 binary와 local path를 API에 직접 반환하지 않는다. ArtifactId와 정책이 적용된 download handle을 사용한다.

7. **Unknown is not retryable**  
   mutating action이 실행됐는지 확정할 수 없으면 성공/실패를 추측하지 않고 `OUTCOME_UNKNOWN`으로 종료한다.

8. **No hidden reuse after taint**  
   cleanup 실패, unmanaged target, CDP desync, browser-global mutation, unknown extension state가 발생한 shard는 drain한다.

9. **No route means no bypass**  
   network security는 Chromium proxy 설정만 믿지 않고 outer netns에서 direct route 자체를 제거한다.

10. **Fencing everywhere**  
    session placement, worker ownership, human control, approval, stale node/snapshot은 epoch/version/generation으로 fencing한다.

11. **Fail closed at policy boundaries**  
    auth, network policy, secret resolution, placement ownership, target attribution이 불확실하면 실행하지 않는다.

12. **Degrade explicitly**  
    Redis/object storage/audit sink 등 부분 장애 시 허용되는 기존 기능과 금지되는 신규 기능을 명확히 정의한다.

13. **Observability by design**  
    operation/session/action/shard/target/artifact/control state transition을 metric, trace, structured log, audit event로 연결한다.

14. **Rollback is a runtime capability**  
    shared-context 문제가 발견되어도 바이너리 rollback 없이 `max_contexts_per_shard=1`로 축소할 수 있어야 한다.

# 6. 전체 구조

```text
                                  Agent / Skill Host
                                          │
                                   mTLS + short JWT
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Browser Gateway                                                         │
│ Auth │ Policy │ Idempotency │ Operation │ Regional DRR │ Session Router │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ fenced internal RPC
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
┌───────────────────────────────┐  ┌───────────────────────────────┐
│ Browser Worker A              │  │ Browser Worker B              │
│ Reservations / Sessions       │  │ Reservations / Sessions       │
│ SessionExecutor / Admission   │  │ SessionExecutor / Admission   │
│ Target / Artifact clients     │  │ Target / Artifact clients     │
└──────────────┬────────────────┘  └──────────────┬────────────────┘
               │ fixed launch/control protocol    │
               ▼                                  ▼
┌───────────────────────────────┐  ┌───────────────────────────────┐
│ Sandbox Supervisor            │  │ Sandbox Supervisor            │
│ ┌───────────────────────────┐ │  │ ┌───────────────────────────┐ │
│ │ BrowserShard A1           │ │  │ │ BrowserShard B1           │ │
│ │ user/pid/mount/net ns     │ │  │ │ user/pid/mount/net ns     │ │
│ │ cgroup + private fs/shm   │ │  │ │ cgroup + private fs/shm   │ │
│ │ Chromium                  │ │  │ │ Chromium                  │ │
│ │ ├─ Context S1            │ │  │ │ ├─ Context S4            │ │
│ │ ├─ Context S2            │ │  │ │ └─ Context S5            │ │
│ │ └─ Context S3            │ │  │ └───────────────────────────┘ │
│ └───────────────────────────┘ │  └───────────────────────────────┘
└──────────────┬────────────────┘
               │ shard netns에서 유일하게 허용된 외부 경로
               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Egress Policy Proxy                                                     │
│ route identity │ DNS/IP policy │ connect target validation │ bandwidth │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   ▼
                                Internet

Artifact Store / Secret Store / PostgreSQL / Redis / Audit Sink는
Gateway/Worker의 별도 trusted service channel을 통해 접근한다.
```

## 6.1 주요 실행 경로

### Session 생성

```text
POST /sessions
 → auth/policy/idempotency
 → CreateSessionOperation
 → tenant DRR queue
 → worker reservation
 → compatible shard 선택 또는 새 shard 생성
 → BrowserContext 생성
 → primary target bootstrap 완료
 → Session READY
```

### Action 실행

```text
POST /sessions/{id}/actions
 → ActionId/idempotency
 → placement fencing
 → SessionExecutor queue
 → policy/approval
 → ActionAdmission
 → READY_TO_DISPATCH durable intent
 → MAY_HAVE_EXECUTED
 → CDP/feature operation
 → known result 또는 OUTCOME_UNKNOWN
```

### Worker loss

```text
worker ownership lease expiry
 → 신규 RPC/route 차단
 → shard egress routes revoke
 → sandbox supervisor cgroup.kill
 → directory placement LOST
 → in-flight mutating action OUTCOME_UNKNOWN
 → sessions FAILED(worker_lost)
```

## 6.2 배포 모드

### 개발·초기 운영: Modular deployment

개발 환경에서는 gateway와 worker를 하나의 `browserd` binary에서 실행할 수 있다. 다만 Chromium은 개발 모드에서도 가능하면 동일한 ShardSandbox abstraction을 사용한다.

```text
browserd all-in-one
├─ API gateway
├─ scheduler/operation
├─ worker/session executor
├─ sandbox supervisor client
├─ browser fleet
├─ viewer
└─ artifact/network adapters
```

Production에서 all-in-one process를 쓰면 해당 process가 worker control-plane failure domain이 된다는 점을 운영 문서에 명시한다.

### 확장 운영: Gateway/Worker/Sandbox 분리

- Gateway: stateless API + regional scheduling. 여러 replica 사용 가능
- Worker: host-local session/action control plane
- Sandbox Supervisor: 최소 권한으로 shard namespace/cgroup lifecycle 관리
- Egress Proxy: connect-target를 검증하는 mandatory data plane
- Redis: operation/routing/reservation/idempotency/revocation coordination
- PostgreSQL: tenant/policy/API key/usage/audit index
- Object storage: artifacts/checkpoints

live BrowserContext와 target registry의 실제 상태는 Worker/Chromium이 source of truth다. Redis는 routing/control metadata이며 browser state snapshot이 아니다.

# 7. Rust workspace 구조

```text
browserd/
├─ Cargo.toml
├─ crates/
│  ├─ browserd-core/             # ID, errors, state, policy, invariants
│  ├─ browserd-api/              # HTTP/RPC schema, OpenAPI
│  ├─ browserd-auth/             # JWT/capability/mTLS binding
│  ├─ browserd-operations/       # CreateSessionOperation, async operation API
│  ├─ browserd-cdp/              # bounded CDP transport/protocol
│  ├─ browserd-targets/          # TargetManager, target/frame registry
│  ├─ browserd-chromium/         # Chromium artifact/launch/process lifecycle
│  ├─ browserd-sandbox/          # namespace/cgroup sandbox contract/client
│  ├─ browserd-fleet/            # worker reservation, shard/session scheduler
│  ├─ browserd-session/          # SessionRecord, SessionExecutor, lifecycle
│  ├─ browserd-actions/          # typed actions, action ledger, uncertainty
│  ├─ browserd-viewer/           # screencast, IME/input, control lease
│  ├─ browserd-artifacts/        # artifact state machine/quota/store adapter
│  ├─ browserd-egress/           # route binding/policy proxy integration
│  ├─ browserd-policy/           # approval proposal, policy snapshots
│  ├─ browserd-observability/    # metrics, trace, audit WAL
│  └─ browserd-features/         # PDF/screenshot/scrape/checkpoint modules
├─ bins/
│  ├─ browser-gateway/
│  ├─ browser-worker/
│  ├─ browser-sandboxd/
│  ├─ browser-egressd/
│  └─ browserd/
├─ sdk/
│  ├─ typescript/
│  └─ python/
├─ viewer-web/
└─ tests/
   ├─ integration/
   ├─ security/
   ├─ chaos/
   ├─ compatibility/
   └─ load/
```

## 7.1 제안 기술 스택

- async runtime: Tokio
- HTTP/WebSocket: Axum + Tower
- serialization: Serde
- API schema: OpenAPI generator를 지원하는 Rust schema 도구
- tracing: `tracing` + OpenTelemetry
- database: PostgreSQL adapter
- ephemeral coordination: Redis adapter
- CDP: pinned protocol schema 기반 `CdpDriver` + `TargetManager`
- object storage: S3-compatible adapter
- sandbox: Linux namespace/cgroup v2 abstraction; backend는 직접 구현 또는 검증된 runtime adapter 가능
- egress proxy: Rust async proxy 또는 별도 검증된 proxy core를 policy adapter 뒤에 사용

특정 crate 버전은 구현 시작 시 lockfile과 dependency review로 고정한다.

## 7.2 내부 actor/ownership 권장 구조

```text
WorkerSupervisor
└─ ShardActor
   ├─ CDP transport 단독 소유
   ├─ TargetManager
   ├─ TargetRegistry
   ├─ DownloadRegistry
   └─ SessionActor N
      ├─ SessionExecutor
      ├─ ActionLedger
      ├─ Page/Frame/NodeRegistry
      ├─ ControlLease
      └─ ArtifactNamespace
```

CDP reader가 직접 business logic을 실행하지 않는다. event는 bounded queue를 통해 관련 actor로 전달하며 oversized message/event flood가 worker memory를 무제한 사용하지 못하게 한다.

# 8. 핵심 도메인 모델

## 8.1 식별자

- `TenantId`: UUIDv7
- `PrincipalId`: UUIDv7 또는 외부 IdP subject mapping
- `OperationId`: UUIDv7
- `SessionId`: UUIDv7
- `ShardId`: worker-local UUIDv7
- `PageId`: opaque random ID
- `ActionId`: UUIDv7
- `ArtifactId`: UUIDv7
- `SnapshotId`: opaque random ID
- `LeaseId`: opaque random ID
- `WorkerId`: stable deployment identity

외부에는 Chromium context/target/process/frame/backend-node ID를 직접 노출하지 않는다.

## 8.2 CreateSessionOperation

```rust
struct CreateSessionOperation {
    id: OperationId,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    request_hash: RequestHash,
    state: CreateOperationState,
    requested_isolation: IsolationProfile,
    effective_isolation: Option<IsolationProfile>,
    resource_request: ResourceRequest,
    session_id: Option<SessionId>,
    error: Option<OperationError>,
    created_at: DateTime<Utc>,
    deadline_at: DateTime<Utc>,
}
```

`QUEUED`, `RESERVING`, `CREATING`은 live Session이 아니라 이 operation의 상태다.

## 8.3 SessionRecord

```rust
struct SessionRecord {
    id: SessionId,
    tenant_id: TenantId,
    principal_id: PrincipalId,
    lifecycle: SessionLifecycle,
    execution: SessionExecution,
    control: SessionControl,
    incarnation: u64,
    placement: Placement,
    primary_page_id: Option<PageId>,
    created_at: DateTime<Utc>,
    last_activity_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    idle_expires_at: DateTime<Utc>,
    effective_workload_class: WorkloadClass,
    policy_snapshot_id: PolicySnapshotId,
    metadata: Map<String, String>,
}
```

`incarnation`은 live ownership/target handle fencing에 사용한다. v1에서 worker crash 후 checkpoint restore는 기본적으로 새 SessionId를 만들기 때문에 incarnation을 crash recovery용 transparent identity로 사용하지 않는다. v1에서는 증가 경로가 없어 값이 항상 1이다. field와 fencing 검증 로직은 향후 in-place re-attach/recovery를 프로토콜 변경 없이 도입하기 위한 예약이다.

## 8.4 Placement

```rust
struct Placement {
    worker_id: WorkerId,
    worker_epoch: u64,
    shard_id: ShardId,
    placement_version: u64,
    state: PlacementState,
}
```

Gateway→Worker session RPC에는 `worker_epoch`, `placement_version`, `session_incarnation`이 반드시 포함된다.

## 8.5 BrowserShard

```rust
struct BrowserShard {
    id: ShardId,
    worker_id: WorkerId,
    lifecycle: ShardLifecycle,
    health: ShardHealth,
    admission: ShardAdmission,
    compatibility_key: CompatibilityKey,
    browser: BrowserHandle,
    sandbox: ShardSandboxHandle,
    sessions: HashMap<SessionId, ContextSession>,
    created_at: Instant,
    total_contexts_created: u64,
    memory_current_bytes: u64,
    memory_peak_bytes: u64,
    cpu_ewma: f64,
    target_count: u32,
    cgroup: CgroupHandle,
}
```

`FULL`은 저장되는 lifecycle state가 아니다. admission 상태와 resource availability에서 파생한다.

## 8.6 CompatibilityKey

같은 Chromium process를 공유할 수 있는 process-level 설정을 표현한다.

```text
chromium_artifact_digest
cdp_schema_digest
headless_mode
extension_bundle_digest
font_bundle_digest
gpu_profile
launch_profile_digest
sandbox_profile
network_class
certificate_profile
browser_global_feature_digest
```

다음은 대체로 context/target/session 단위지만 실제 CDP 적용 범위에 따라 TargetManager가 관리한다.

```text
proxy route
viewport/device metrics
locale
timezone
user agent/client hints
permissions
storage restore
download behavior
network policy
```

## 8.7 ContextSession

```rust
struct ContextSession {
    id: SessionId,
    context: BrowserContextHandle,
    pages: HashMap<PageId, PageHandle>,
    primary_page: Option<PageId>,
    executor: SessionExecutor,
    action_ledger: ActionLedger,
    control: ControlLeaseState,
    artifact_namespace: ArtifactNamespace,
    target_registry: SessionTargetRegistry,
    cleanup_state: CleanupState,
}
```

## 8.8 NodeHandle

외부 `node_ref`는 signed 구조체를 그대로 노출하는 대신 random opaque handle을 권장한다.

```rust
struct NodeHandleRecord {
    session_id: SessionId,
    session_incarnation: u64,
    page_id: PageId,
    target_incarnation: u64,
    frame_key: InternalFrameKey,
    frame_document_epoch: u64,
    url_revision: u64,
    backend_node_id: BackendNodeId,
    snapshot_id: SnapshotId,
    expires_at: Instant,
}
```

NodeHandle table은 session-local bounded LRU/TTL로 제한한다.

## 8.9 ControlLease

```rust
struct ControlLease {
    lease_id: LeaseId,
    lease_epoch: u64,
    holder_principal: PrincipalId,
    page_id: PageId,
    expires_at: Instant,
    last_input_sequence: u64,
}
```

## 8.10 ResourceRequest

단일 scalar workload weight 외에 실제 admission은 resource vector를 사용한다.

```rust
struct ResourceRequest {
    context_slots: u32,
    memory_reservation_bytes: u64,
    page_slots: u32,
    target_slots: u32,
    viewer_slots: u32,
    process_slots: u32,
    action_class: ActionResourceClass,
}
```

# 9. 상태 머신

상태를 하나의 거대한 enum으로 합치지 않는다. lifecycle, health/placement, execution, control을 독립 축으로 관리해 불가능한 조합은 invariant로 차단한다.

## 9.1 BrowserShard lifecycle

```text
STARTING
  │ readiness/self-test 성공
  ▼
ACTIVE
  │ age/taint/deploy/resource policy
  ▼
DRAINING
  │ sessions == 0
  ▼
STOPPING
  ▼
DEAD
```

별도 축:

```text
ShardHealth:    HEALTHY | DEGRADED | TAINTED | COMPROMISED
ShardAdmission: OPEN | CLOSED
```

`capacity_available=false`는 `FULL` 상태를 저장하지 않고 resource 계산에서 파생한다.

### DRAINING 진입 조건

- `max_browser_age` 초과
- `max_contexts_created_lifetime` 초과
- soft memory/pressure 임계치 지속 초과
- context cleanup 실패 또는 orphan target
- unmanaged/unknown target 관측
- browser-global preference/feature mutation
- worker rolling deployment
- 높은 crash/protocol error rate
- compatibility/security kill switch

### 즉시 종료 조건

- cgroup hard memory/PID limit 또는 OOM group kill
- Chromium browser process 비정상 종료
- CDP transport irrecoverable failure/desync
- security violation으로 shard 상태를 신뢰할 수 없음
- worker ownership lease 상실

즉시 종료 시 해당 shard의 live session은 `FAILED`가 되고 in-flight mutating action은 결과를 입증할 수 없으면 `OUTCOME_UNKNOWN`이 된다.

## 9.2 CreateSessionOperation

```text
ACCEPTED
   ▼
QUEUED
   ▼
RESERVING
   ├─ capacity race → QUEUED
   ▼
CREATING
   ├─ success → SUCCEEDED(session_id)
   ├─ deadline → TIMED_OUT
   ├─ cancel before commit → CANCELLED
   └─ fatal → FAILED
```

Operation이 `SUCCEEDED`된 뒤에만 live Session이 외부에서 READY로 보인다.

## 9.3 Session lifecycle/placement

```text
SessionLifecycle:
  CREATING → READY → CLOSING → CLOSED
       └────────────── fatal ─→ FAILED

SessionPlacement:
  RESERVED → ATTACHED → LOST
```

READY/BUSY/HUMAN 등의 조합은 lifecycle 하나에 표현하지 않는다.

## 9.4 Session execution

```text
IDLE
  │ action accepted
  ▼
RUNNING(action_id)
  ├─ approval 필요 → PENDING_APPROVAL(action_id)
  ├─ known completion → IDLE
  └─ semantic uncertainty → RECONCILIATION_REQUIRED(action_id)

RECONCILIATION_REQUIRED(action_id)
  ├─ resolve 확정(§15.11) → IDLE
  └─ session close → CLOSING
```

`RECONCILIATION_REQUIRED`에서는 read/snapshot과 explicit resolve(§15.11)/close만 허용하고 새로운 mutating action은 차단한다. 해제 경로는 resolve와 close 두 가지뿐이다(D-28).

## 9.5 Action state

```text
ACCEPTED
  ▼
QUEUED
  ├─ approval → PENDING_APPROVAL
  ▼
READY_TO_DISPATCH
  ▼  dispatch intent를 먼저 기록
MAY_HAVE_EXECUTED
  ├─ SUCCEEDED
  ├─ FAILED_KNOWN
  ├─ CANCELLED_CONFIRMED
  └─ OUTCOME_UNKNOWN
```

`CANCELLED_BEFORE_DISPATCH`는 `MAY_HAVE_EXECUTED` 이전에만 사용할 수 있다.

`OUTCOME_UNKNOWN`은 터미널 상태다. §15.11 resolve는 browserd의 outcome 주장을 바꾸지 않으며, ledger에 caller resolution annotation(`resolved_as`, `resolved_by`, `resolved_at`, `basis`)만 추가한다.

## 9.6 Human control

```text
AGENT_CONTROL(epoch=N)
   │ acquire가 SessionExecutor barrier를 통과
   ▼
HUMAN_CONTROL(epoch=N+1)
   │ release / expiry / disconnect
   ▼
AGENT_CONTROL(epoch=N+2)
```

- 한 session에 동시에 하나의 controller만 존재한다.
- observer viewer는 여러 명 가능하다.
- human control 중 새 agent mutating action은 기본 `423 session_controlled_by_human`이다.
- control acquire는 현재 실행 중 원자 action 뒤에서 linearize한다.
- 모든 input event는 현재 lease epoch와 monotonically increasing input sequence를 요구한다.
- disconnect/expiry 시 mouse/key/modifier/IME composition state를 best-effort reset한다.

# 10. Isolation Profile

Isolation은 placement뿐 아니라 network/extension/reuse policy와 함께 해석한다. 스케줄러는 tenant policy가 허용한 profile보다 약한 격리를 선택할 수 없다.

## 10.1 `shared_context`

```text
Outer-sandboxed Chromium shard
├─ Tenant A / Session A1
├─ Tenant B / Session B1
└─ Tenant C / Session C1
```

- 기본 효율 profile
- BrowserContext storage/session 격리
- 동일 Chromium browser-process compromise/crash blast radius 공유
- session별 CPU/RAM/disk hard isolation 비보장
- Chrome extension 금지
- arbitrary upstream proxy 금지
- public browserd-managed network class만 허용

## 10.2 `tenant_dedicated_shard`

```text
Outer-sandboxed Chromium shard
├─ Tenant A / Session A1
├─ Tenant A / Session A2
└─ Tenant A / Session A3
```

- 서로 다른 tenant는 같은 shard에 배치하지 않는다.
- 동일 tenant의 여러 session이 같은 shard를 공유하되, 각 session은 여전히 별도 BrowserContext로 분리된다.
- 운영자가 승인한 extension bundle 허용 가능
- custom allowlist/certificate profile 가능
- context 간 resource hard isolation은 여전히 제공하지 않는다.

## 10.3 `dedicated_process`

```text
Outer-sandboxed Chromium shard
└─ Tenant A / Session A1
```

- session 하나가 Chromium 하나를 독점
- raw CDP는 여전히 제공하지 않음
- 고보안, no-reuse, 특수 process-level 설정용
- session 종료 후 `no_reuse` 정책이면 shard 즉시 종료

## 10.4 `dedicated_worker`

- tenant 또는 특정 network/security class가 worker pool을 독점한다.
- private network, customer-managed proxy/certificate, hardware GPU, 특수 extension은 이 tier를 우선 사용한다.
- worker 내부에서 다시 tenant-dedicated 또는 dedicated-process policy를 적용할 수 있다.

## 10.5 Orthogonal isolation attributes

실제 scheduler compatibility는 하나의 enum만 보지 않고 다음 축을 계산한다.

```text
placement_isolation
network_class
extension_profile
gpu_profile
persistence_profile
certificate_profile
reuse_policy = cross_tenant | same_tenant_only | no_reuse
```

`force_dedicated_process=true` kill switch가 켜지면 모든 신규 session은 기존 requested profile과 무관하게 1 session/Chromium으로 배치한다.

# 11. Admission, quota, queue

## 11.1 Session 생성 검사 순서

```text
CreateSession
  │
  ├─ authentication / capability
  ├─ tenant plan + current emergency deny
  ├─ idempotency → OperationId 결정
  ├─ per-principal rate limit
  ├─ tenant active-session quota
  ├─ tenant queued-operation quota
  ├─ requested → effective resource/isolation profile 계산
  ├─ regional/global queue capacity
  └─ admit 또는 tenant DRR queue
```

Client가 보낸 `workload_class`는 hint다. `effective_workload_class`와 `ResourceRequest`는 tenant plan, enabled feature, isolation, historical observation을 포함해 server가 결정한다.

## 11.2 Gateway queue와 공정성

장기 CreateSession 대기는 Gateway/Regional Scheduler가 소유한다. Worker는 장기 queue를 갖지 않고 짧은 reservation만 처리한다.

단일 전역 FIFO 대신 tenant별 FIFO subqueue + Deficit Round Robin을 사용한다.

초기 admission cost hint:

| Isolation/workload | DRR cost |
|---|---:|
| shared + light | 1 |
| shared + interactive | 2 |
| shared + heavy | 4 |
| tenant_dedicated_shard | 6 |
| dedicated_process | 8 |
| dedicated_worker | policy-defined |

이 scalar cost는 fairness를 위한 queue debit이며 실제 worker capacity 판단은 `ResourceRequest` vector를 사용한다.

- tenant plan별 weight 가능
- 동일 plan 내 starvation 금지
- tenant별 queued-operation 상한 필요
- queue timeout/operation deadline 적용
- multi-gateway에서는 queue ownership을 하나의 regional scheduler leader 또는 atomic scheduler backend로 직렬화한다.

## 11.3 Worker reservation

Gateway가 stale worker metric만 보고 즉시 placement를 확정하지 않는다.

```text
Gateway
  │ ReserveSession(operation_id, compatibility, ResourceRequest)
  ▼
Worker
  │ capacity 원자 확인/선점
  └─ reservation_token + placement + expiry
  ▲
Gateway
  │ CommitReservation(reservation_token)
  ▼
Worker → context create
```

Reservation invariant:

- token은 worker epoch와 worker-local nonce에 bind
- 짧은 TTL
- commit/cancel/expiry는 idempotent
- expiry 시 capacity 자동 반환
- 같은 OperationId의 중복 reservation은 하나만 유효
- worker drain 시작 후 신규 reservation 거부

## 11.4 Shard 선택

후보 shard는 다음을 모두 만족해야 한다.

- lifecycle `ACTIVE`
- admission `OPEN`
- health `HEALTHY` 또는 정책상 허용된 `DEGRADED`
- CompatibilityKey 일치
- isolation/reuse profile 위반 없음
- context/page/target/resource reservation 여유
- `memory.current`와 memory pressure가 soft threshold 미만
- browser age가 drain threshold 미만
- extension/network/certificate/GPU profile 호환

후보 score 초기안:

```text
capacity_score = max(
  context_slots_used / max_context_slots,
  target_slots_used / max_target_slots,
  memory_current / soft_memory_limit,
  reserved_memory / memory_reservation_budget
)

load_score = capacity_score
           + 0.25 * normalized_cpu_ewma
           + pressure_penalty
           + age_penalty
```

후보가 없고 worker/host envelope가 허용하면 새 shard를 생성한다. 아니면 operation을 queue에 돌려보내거나 deadline/capacity error로 종료한다.

## 11.5 Host resource envelope

Shard hard limit의 단순 합이 host 물리 자원을 넘지 않도록 worker는 다음 allocatable budget을 유지한다.

```text
host_allocatable_memory
 = host_total
 - OS reserve
 - worker/sandbox/egress reserve
 - artifact/temp reserve
 - emergency headroom
```

```text
sum(active + reserved shard memory) <= host_allocatable * configured_overcommit
```

CPU, PIDs, disk/tmpfs도 유사한 host-level envelope를 가진다.

## 11.6 ActionAdmission

Session이 READY라고 모든 resource-heavy action을 즉시 실행하지 않는다.

ActionAdmission 대상 예:

```text
PDF
full-page screenshot
large DOM/accessibility snapshot
large scrape/readability
checkpoint
large upload/download finalization
malware scan
viewer screencast/encoding resource
```

초기 제한 예:

```text
per shard:
- concurrent PDF = 1
- concurrent full-page screenshot = 1
- concurrent large snapshot = 2

per worker:
- concurrent PDF = benchmark-defined
- artifact bytes in flight = bounded
- temp bytes in flight = bounded
- active screencast streams = bounded
```

ActionAdmission wait는 session action execution deadline과 별도의 admission deadline을 가진다.

## 11.7 Preemption

일반 capacity 확보 목적으로 실행 중 session을 강제 종료하지 않는다.

예외:

- hard memory/PID/disk pressure
- security violation
- worker ownership 상실
- 관리자 강제 종료
- tenant quota emergency enforcement
- session TTL
- runaway target/resource abuse

Shared-context의 한 session이 shard 전체를 위협하면 offending session을 먼저 close하고, resource가 정상화되지 않으면 shard 전체를 종료한다.

## 11.8 Warm shard pool

warm context 생성 p95 목표(§2.1)는 warm shard가 실제로 존재할 때만 의미가 있다. Worker는 CompatibilityKey별 warm spare shard 수를 정책으로 유지한다.

- pool 크기는 최근 CreateSession 도착률과 cold start 시간으로 산정하되 host resource envelope(§11.5) 안에서만 유지한다.
- warm shard에도 browser age/lifetime context/recycle 규칙을 동일하게 적용한다.
- `force_dedicated_process` 등 kill switch 발동 시 비호환 pool은 즉시 drain한다.
- pool 부족으로 cold path에 진입한 생성 비율을 관측한다(`browserd_session_cold_creates_total`).

# 12. 초기 limit 제안

아래 값은 production 확정값이 아니라 첫 benchmark/fault-test를 위한 초기값이다.

## 12.1 Session/Shard 기본값

| 항목 | 초기값 |
|---|---:|
| max contexts per shard | 8, runtime kill switch로 1 가능 |
| max pages per session | 8 |
| max total pages per shard | 32 |
| max frames per session | 64 |
| max workers per session | 16 |
| max service workers per session | 8 |
| max total targets per session | 96 |
| max total targets per shard | 256 |
| max target creations per 10s/session | 64 |
| default session TTL | 30분 |
| default idle timeout | 10분 |
| create operation deadline | 30초 기본, API에서 policy 범위 내 조정 |
| browser max age | 2시간 |
| lifetime contexts per browser | 500 |

## 12.2 Action/API 제한

| 항목 | 초기값 |
|---|---:|
| default execution timeout | 30초 |
| navigation execution timeout | 45초 |
| PDF/scrape execution timeout | 60초 |
| max evaluate source, privileged only | 64 KiB |
| max evaluate result | 1 MiB |
| max selector length | 8 KiB |
| max pending actions per session | 64 |
| max pending CDP commands per shard | benchmark-defined, bounded |
| max CDP message/event size | protocol/feature별 bounded |

## 12.3 Memory/process/filesystem

| 항목 | 초기값 |
|---|---:|
| soft shard memory | 2.5 GiB 또는 shard budget 70% |
| hard shard memory.max | 3.5 GiB 또는 shard budget 90% |
| memory.oom.group | 1 |
| pids.max | benchmark 기반 고정값 |
| private `/dev/shm` | 512 MiB 초기 |
| profile/temp filesystem quota | 2 GiB 초기 |
| temp inode quota | 별도 상한 |
| RLIMIT_NOFILE | target/page/download benchmark 기반 상한 |
| RLIMIT_CORE | 0 production |

`soft shard memory`는 cgroup `memory.current`/pressure를 기준으로 한다. RSS라는 이름을 사용하지 않는다.

초기 hard 3.5 GiB에서 8 context 밀도는 light 중심 workload를 가정한 상한이다. interactive/heavy 혼합에서는 세션당 예산이 약 440 MiB에 불과하고 `memory.oom.group=1` 특성상 한 세션의 스파이크가 co-tenant를 포함한 shard 전체를 함께 종료시킨다. 따라서 soft-threshold 기반 offending-session eviction이 할당 스파이크보다 빠른지(detection→eviction latency)를 벤치마크 항목에 포함하고, confirmed density가 2~4에 머물거나 shard 예산을 상향해야 할 수 있음을 capacity 계획의 기본 전제로 둔다. heavy workload class에는 더 큰 shard budget profile 또는 더 낮은 밀도를 적용할 수 있다.

## 12.4 Artifact/Network

| 항목 | 초기값 |
|---|---:|
| max upload per file | 50 MiB |
| max download per file | 100 MiB |
| max committed artifacts per session | 500 MiB |
| max artifact bytes in flight/session | 128 MiB 초기 |
| max screenshot dimensions | 1920×1080 기본, feature policy로 확대 |
| max screenshot pixels | 별도 hard limit |
| max inline snapshot screenshot bytes | 512 KiB 초기 |
| network concurrent connections/session | benchmark-defined bounded |
| egress bytes/sec/session | plan-defined |
| total egress/session | plan-defined |
| DNS/connection creation rate | bounded |

## 12.5 Viewer

| 항목 | 초기값 |
|---|---:|
| viewer target FPS | 12 |
| viewer JPEG quality | 70 |
| viewer rendered target | 1920×1080 |
| frame queue per viewer | latest 1~2 frame |
| human control lease | 60초 heartbeat 갱신 |
| max concurrent observers per session | 4 초기 |
| viewer input message rate | 240 msg/10초 초기 |
| viewer stream bandwidth | plan-defined |

## 12.6 Workload class

| Class | Queue cost hint | 예시 |
|---|---:|---|
| light | 1 | 단순 screenshot, 짧은 scrape |
| interactive | 2 | 일반 CUA/session |
| heavy | 4 | SPA, dashboard, worker 많은 사이트 |

실제 resource admission은 workload class 하나가 아니라 `ResourceRequest`와 runtime observation을 사용한다. 관측으로 class를 자동 상향할 수 있으나 동일 session에서 자동 하향은 하지 않는다. isolation 자동 격상은 §13.7을 따른다.

# 13. Chromium 프로세스와 Shard Sandbox 관리

## 13.1 Launch 정책

- Chromium executable/digest/version/revision을 명시적으로 고정한다.
- CDP browser/js protocol schema digest도 artifact에 포함한다.
- `--remote-debugging-pipe`를 우선 사용한다.
- public/host-wide remote debugging port를 열지 않는다.
- shard마다 private ephemeral `user-data-dir`을 사용한다.
- user-data-dir은 shard outer sandbox 안에만 mount한다.
- Chromium sandbox는 항상 활성화한다.
- worker/host secret 또는 cloud credential을 Chromium environment에 전달하지 않는다.
- arbitrary tenant launch arg를 허용하지 않는다.
- arbitrary tenant extension을 허용하지 않는다.
- shared tier에서는 hardware GPU를 기본 비활성/software path로 두고 hardware GPU는 별도 worker profile로 운영한다.
- back/forward cache는 launch profile에서 비활성화한다(D-29). 문서 epoch/bootstrap 전제(§14.2, §14.4)를 단순하게 유지하기 위해서이며, 재활성화는 compatibility artifact 변경으로 취급한다.

## 13.2 Outer ShardSandbox contract

모든 production shard는 최소 다음 조건을 만족한다.

```text
- user namespace 또는 동등한 shard별 UID isolation
- PID namespace
- mount namespace
- network namespace
- private /tmp
- size-limited private /dev/shm
- quota-backed private profile/temp/download filesystem
- readonly Chromium/font/certificate runtime mounts
- no_new_privs
- 불필요 Linux capability 0
- 다른 shard/worker service Unix socket 미노출
- cgroup v2 resource boundary
- mandatory egress proxy 외 network route 없음
```

`container-per-session`은 요구하지 않지만 `sandbox-per-shard`는 production invariant다.

## 13.3 cgroup/rlimit

- `memory.high`, `memory.max`, `memory.swap.max`
- `memory.oom.group=1`
- `pids.max`
- `cpu.max`, `cpu.weight`
- worker/supervisor가 `memory.current`, `memory.peak`, `memory.events`, PSI를 관측
- `RLIMIT_NOFILE`, `RLIMIT_CORE=0`
- 종료 시 `cgroup.kill` 사용 가능

Hard OOM/PID exhaustion 후 일부 renderer만 살아 있는 shard를 재사용하지 않는다.

## 13.4 Sandbox Supervisor와 worker ownership

Worker가 자기 자신과 동일한 lifecycle로 Chromium을 직접 소유한다고 가정하지 않는다. Sandbox Supervisor는 최소 권한의 shard lifecycle 서비스로 다음을 제공한다.

```text
create_shard(LaunchSpec, owner_lease)
renew_owner_lease(shard_id, worker_epoch)
kill_shard(shard_id, reason)
inspect_resources(shard_id)
```

여기서의 lease는 worker↔supervisor 간 host-local **Supervisor Lease**로, §28의 Directory Lease와 별개다. `supervisor_lease_ttl ≤ directory_lease_ttl`을 invariant로 유지해(D-32) local egress revoke/kill이 전역 LOST 처리보다 늦지 않게 한다.

Supervisor Lease가 갱신되지 않으면 supervisor는:

1. 해당 shard의 egress route를 revoke하도록 요청한다.
2. grace가 필요 없는 security/worker-loss path에서는 cgroup 전체를 kill한다.
3. namespace/mount/temp를 정리한다.
4. cleanup 결과를 audit/metric으로 남긴다.

worker SIGKILL 후 Chromium이 계속 외부 side effect를 수행하는 상태를 허용하지 않는다.

Egress route는 shard identity에 bind된다. egressd는 supervisor의 revoke 요청과 별개로, supervisor/worker heartbeat에 연동된 route TTL 갱신을 defense-in-depth로 적용할 수 있다.

## 13.5 CDP transport hardening

Chromium/CDP도 비정상 또는 compromise된 peer가 될 수 있다고 가정한다.

- protocol message 최대 크기
- pending request 개수 상한
- bounded event queue
- event type별 payload validation
- target/frame registry size limit
- writer/read timeout
- command sequence ID wrap/duplicate 방어
- parser panic가 worker process 전체를 죽이지 않도록 오류 경계

CDP transport가 irrecoverable desync되면 연결 재사용을 시도하지 않고 shard를 종료한다.

## 13.6 Taint 조건

다음 중 하나면 `health=TAINTED`, `admission=CLOSED`, lifecycle을 `DRAINING`으로 전환한다.

- context dispose 실패
- cleanup 후 target/frame/download가 남음
- attribution 불가능한 target/download
- browser-global preference가 session 때문에 변경됨
- Feature hook이 browser state를 불확실하게 만듦
- CDP event stream gap/protocol desync
- 비정상 download handler 상태
- memory/resource leak slope 임계치 초과
- extension/browser-global state cleanup 불확실

Security compromise가 의심되면 drain이 아니라 즉시 kill한다.

## 13.7 Taint attribution과 abuse escalation

Taint는 방어 장치인 동시에, 악용하면 값싼 fleet DoS 수단이 된다. 반복적인 shard taint/crash는 recycle 비용과 co-resident session 강제 종료를 유발하기 때문이다.

- taint/crash/즉시 종료 event에는 가능한 경우 유발 session/tenant attribution을 기록한다. attribution 불가능 사례는 그 자체를 별도 신호로 집계한다.
- tenant별 taint 유발률/shard crash 동반률을 관측 지표로 유지한다. §26.1의 metric은 low-cardinality reason 단위로 두고, tenant 단위 집계는 usage/audit event로 수행한다.
- 임계치를 넘는 tenant의 신규 session은 requested profile과 무관하게 자동으로 `tenant_dedicated_shard` 이상으로 배치한다(placement penalty). 반복 시 `dedicated_process`를 강제하고 운영 알림을 발생시킨다(D-31).
- escalation과 해제는 audit event다. §12.6의 workload class 자동 상향과 동일하게, 동일 session에서 자동 하향은 하지 않는다.
- 이 정책의 목적은 처벌이 아니라 blast radius 재배치다.

# 14. BrowserContext, Target, Page 관리

## 14.1 Context 생성

Session 생성 시 CDP BrowserContext 기능을 사용한다. Context-level 설정과 target-level 설정을 구분한다.

### Context-level

```text
proxyServer = session route proxy
proxyBypassList = "<-loopback>"
permissions
storage restore
download behavior
```

### Target-level, TargetManager가 모든 새 target에 적용

```text
locale
timezone
user agent/client hints
viewport/device metrics
network/fetch hooks
feature target hooks
```

Context 생성 후 primary page를 생성하지만 **primary target bootstrap이 완료되기 전 Session READY를 반환하지 않는다.**

## 14.2 TargetManager bootstrap barrier

Shard 시작 시 auto-attach를 구성하고 새 target은 가능한 한 `waitForDebuggerOnStart=true` 상태에서 attach한다. 자동 attach된 child target에서도 필요한 재귀 auto-attach를 설정한다.

```text
Target attached, paused
  │
  ├─ browserContextId/context ownership 확인
  ├─ target type 정책 검사
  ├─ page/frame/worker/target quota 검사
  ├─ target incarnation 부여
  ├─ registry 등록
  ├─ locale/timezone/UA/device/network hooks 적용
  ├─ feature hooks 적용
  ├─ lifecycle/dialog/file chooser handler 준비
  └─ runIfWaitingForDebugger
```

어느 단계든 실패하면 target을 실행하지 않고 close한다. ownership을 판단할 수 없는 target은 audit 후 shard를 최소 `DEGRADED`, 필요하면 `TAINTED`로 전환한다.

## 14.3 Target 타입과 limit

기본 정책:

| Target | 정책 |
|---|---|
| page/tab | 허용, page quota |
| iframe/OOPIF | 허용, frame/target quota |
| dedicated/shared worker | 제한 허용 |
| service worker | 제한 허용, cleanup 엄격 |
| prerender | 기본 비활성 또는 target quota에 포함 |
| extension target | shared profile 금지 |
| devtools | 금지 |
| unknown | close + audit + health degrade/taint |

page limit만으로 resource abuse를 막지 않는다. total target와 target creation rate를 함께 제한한다.

## 14.4 Page ID와 frame/document epoch

외부 `PageId`는 random opaque ID다. Chromium target ID와 직접 대응한다고 가정하지 않는다.

각 top-level page에는 다음 revision을 유지한다.

```text
target_incarnation
url_revision
```

각 frame에는 독립적인:

```text
frame_document_epoch
```

를 유지한다. top-level navigation뿐 아니라 iframe navigation/OOPIF target 교체도 stale handle 판정에 반영한다.

`url_revision`은 same-document navigation(pushState/replaceState)에서도 증가하며, node staleness의 필수 조건이 아니다(§14.6). v1에서는 back/forward cache를 비활성화(D-29)해 새 document epoch 없이 문서가 복원되는 경우를 배제한다. BFCache를 재활성화하려면 epoch 규칙 확장이 선행되어야 한다.

## 14.5 Page lifecycle

- popup/new tab도 page limit에 포함
- limit 초과 target은 bootstrap 중 실행 전에 close
- page close는 idempotent
- primary page close 시 남은 page 중 하나를 승격하거나 정책에 따라 새 blank page 생성
- page/target lifecycle event는 SessionExecutor에 ordering event로 전달

## 14.6 Node reference

`node_ref`는 session-local opaque handle이다. 실제 mapping에는 session incarnation, target incarnation, frame document epoch, backend node ID, snapshot ID가 포함된다.

지원 target:

1. `node_ref`
2. strict CSS selector
3. viewport point `(x, y)`

node_ref 유효성 판정의 필수 일치 필드는 `session_incarnation`, `target_incarnation`, `frame_document_epoch`(그리고 attached 여부)다. `url_revision`은 필수 조건이 아니며 진단 metadata와 approval TOCTOU 검증(§24.2)에 사용한다. `snapshot_id` 일치는 snapshot-consistent 실행을 명시적으로 요청한 action에만 요구한다.

오래된 handle은 상황에 따라 다음 오류로 구분한다.

```text
stale_node_ref
stale_document_ref
node_detached
node_not_visible
node_disabled
node_obscured
ambiguous_selector
```

## 14.7 최소 actionability

Playwright semantics 전체를 재현하지 않지만 typed node action은 input dispatch 전에 최소 다음을 수행한다.

1. 정확히 하나의 node resolve
2. frame/document epoch 일치
3. attached 확인
4. visible bounding box 확인
5. scroll into view
6. hit-test 가능한 action point 계산
7. overlay/obscured 여부 검사
8. disabled/aria-disabled 등 기본 상태 검사
9. input dispatch 직전 epoch 재검사

자동 retry는 **실제 input event dispatch 이전**까지만 허용한다.

## 14.8 Context cleanup protocol

```text
1. Session lifecycle=CLOSING
2. 새 agent action/control/input 거부
3. queued action cancel
4. running action quiescence/uncertainty 처리
5. viewer/screencast 종료
6. 진행 중 download 취소/finalize
7. BrowserContext dispose
8. 해당 context의 target/frame/download registry가 0인지 확인
9. session proxy route revoke
10. temp/upload/download materialization 삭제
11. artifact finalize/abort
12. 성공 → CLOSED
13. 잔존/불확실 → shard TAINTED 또는 즉시 kill
```

가능한 Chromium 기능이 있으면 context를 CDP disconnect 시 자동 dispose하는 옵션을 defense-in-depth로 사용할 수 있지만, 이를 cleanup의 유일한 보장으로 사용하지 않는다.

## 14.9 Dialog 정책

JavaScript dialog(alert/confirm/prompt/beforeunload)는 renderer를 blocking하므로 방치하면 navigation/close가 wedging된다.

- 기본 정책은 `auto_dismiss`다. alert는 accept, confirm/prompt/beforeunload는 dismiss하고 dialog event를 기록·발행한다.
- session 옵션 `dialog_policy=hold`이면 dialog를 유지하고 agent의 `handle_dialog`를 기다린다. 처리 없이 execution deadline이 임박하면 auto-dismiss로 강등하고 warning을 남긴다.
- close/cleanup 경로의 page close는 beforeunload에 의해 blocking되지 않는 강제 close primitive를 사용한다.

# 15. Skill API

## 15.1 공통 규칙

- API version: `/v1`
- timestamp: RFC 3339 UTC
- request ID: `X-Request-Id`
- idempotency: `Idempotency-Key`
- tenant ID는 body가 아니라 인증 principal에서 결정
- 큰 binary/local path는 직접 반환하지 않음
- 모든 response에 `trace_id`
- 비동기 작업은 `OperationId`/`ActionId`로 재조회 가능
- SDK는 idempotency key 생성, synchronous wait, operation polling을 숨길 수 있지만 mutating `OUTCOME_UNKNOWN`을 자동 replay하지 않음

## 15.2 Session 생성

```http
POST /v1/sessions
Authorization: Bearer <service capability>
Idempotency-Key: <uuid>
Prefer: wait=500
Content-Type: application/json
```

```json
{
  "isolation": "shared_context",
  "workload_class_hint": "interactive",
  "viewport": {
    "width": 1280,
    "height": 720,
    "device_scale_factor": 1
  },
  "locale": "ko-KR",
  "timezone": "Asia/Seoul",
  "user_agent": null,
  "network_policy_id": "public-web-default",
  "network_class": "public",
  "checkpoint_ref": null,
  "dialog_policy": "auto_dismiss",
  "feature_profile": "standard",
  "ttl_seconds": 1800,
  "idle_timeout_seconds": 600,
  "metadata": {"agent_run_id": "run_123"}
}
```

즉시 생성되면 `201 Created`, 아직 queue/reservation/cold start 중이면 `202 Accepted`를 반환한다.

`201` 예:

```json
{
  "operation": {"id": "op_...", "state": "succeeded"},
  "session": {
    "id": "ses_...",
    "state": "ready",
    "incarnation": 1,
    "primary_page_id": "pg_...",
    "created_at": "...",
    "expires_at": "...",
    "requested_isolation": "shared_context",
    "effective_isolation": "shared_context",
    "capabilities": {
      "screenshot": true,
      "pdf": true,
      "scrape": true,
      "viewer": true,
      "downloads": true,
      "evaluate": false
    }
  },
  "trace_id": "..."
}
```

`202` 예:

```json
{
  "operation": {
    "id": "op_...",
    "state": "queued",
    "poll_url": "/v1/operations/op_..."
  },
  "session": null,
  "trace_id": "..."
}
```

## 15.3 Operation API

```http
GET    /v1/operations/{operation_id}
DELETE /v1/operations/{operation_id}
```

Operation cancel은 commit/dispatch 이전까지만 known-safe하게 취소할 수 있다. 이미 irreversible 단계에 진입했다면 operation type에 맞는 `cancel_pending` 또는 outcome을 반환한다.

## 15.4 Session 조회·종료

```http
GET    /v1/sessions?lifecycle=ready&limit=50&page_token=...
GET    /v1/sessions/{session_id}
DELETE /v1/sessions/{session_id}
```

목록 조회는 인증 principal의 tenant로 한정하고 bounded page size + opaque page token을 사용한다. 필터는 lifecycle/isolation/metadata key 수준의 저비용 조건만 제공한다.

DELETE는 idempotent하다. cleanup이 끝나지 않으면 `202 closing`을 반환한다.

## 15.5 Page API

```http
GET    /v1/sessions/{session_id}/pages
POST   /v1/sessions/{session_id}/pages
DELETE /v1/sessions/{session_id}/pages/{page_id}
POST   /v1/sessions/{session_id}/pages/{page_id}/activate
```

## 15.6 통합 Action API

```http
POST /v1/sessions/{session_id}/actions
Idempotency-Key: <uuid>
Prefer: wait=30000
```

```json
{
  "page_id": "pg_...",
  "if_session_incarnation": 1,
  "execution_timeout_ms": 30000,
  "action": {
    "type": "navigate",
    "url": "https://example.com",
    "wait_until": "domcontentloaded"
  }
}
```

Known synchronous 성공:

```json
{
  "action_id": "act_...",
  "status": "succeeded",
  "session_sequence": 42,
  "started_at": "...",
  "ended_at": "...",
  "result": {
    "url": "https://example.com/",
    "title": "Example Domain",
    "http_status": 200
  },
  "warnings": [],
  "trace_id": "..."
}
```

아직 실행/approval/admission 중이면 `202`와 ActionId를 반환할 수 있다. mutating action이 `OUTCOME_UNKNOWN`으로 종료되면 오류 envelope가 아니라 `200` + `"status": "outcome_unknown"`으로 반환한다(§25.2).

```http
GET /v1/sessions/{session_id}/actions/{action_id}
```

## 15.7 기본 action 종류

### Navigation

```text
navigate
reload
go_back
go_forward
```

### Input

```text
click
double_click
hover
fill
fill_secret
type_text
press_key
scroll
select_option
set_files
focus
blur
check
uncheck
handle_dialog
```

`fill_secret`은 인자로 secret reference만 받는다. secret 원문은 요청/응답/로그에 나타나지 않으며, §23.4의 origin binding 재검증 후에만 주입된다. `browser:act` 외에 `secret:use` scope와 tenant policy가 필요하고 audit event를 남긴다.

### Read

```text
snapshot
get_text
get_html
get_url
get_title
get_attribute
get_properties
get_computed_style
query_all
extract_table
```

Cookie/storage 원문 조회는 기본 action에 포함하지 않는다. 별도 `browser:storage:read` scope와 tenant policy가 필요한 privileged feature다.

### Page lifecycle

```text
new_page
close_page
activate_page
```

### Wait

```text
wait_for
```

`wait_for` 조건은 다음으로 한정한다: `selector_attached`, `selector_visible`, `selector_hidden`, `url_matches(pattern)`, `load_state(domcontentloaded|load)`, `network_quiet(bounded heuristic)`. timeout은 action execution deadline 이하의 bounded 값이며, `network_quiet`은 보장이 아니라 관측 기반 heuristic임을 명시한다.

### Privileged execution

```text
evaluate
```

`evaluate`는 `standard` feature profile에서 비활성이다. `browser:evaluate` scope + privileged feature/policy가 모두 있어야 한다.

### Feature action

```text
screenshot
pdf
scrape
checkpoint
```

## 15.8 Action serialization

- session의 mutating action과 control transition은 `SessionExecutor` 하나가 linearize한다.
- read action도 기본 queue를 통과해 session sequence를 가진다.
- 향후 read-only concurrency는 명시적으로 safe한 action에만 추가한다.
- action에는 monotonically increasing `session_sequence`를 부여한다.
- target/page lifecycle event가 action과 race할 때 stale epoch 검사를 사용한다.

## 15.9 Idempotency와 uncertainty

- CreateSession: `(tenant_id, idempotency_key)` → OperationId
- Action: `(tenant_id, session_id, idempotency_key)` → ActionId
- 동일 key + 다른 canonical body → `409 idempotency_conflict`
- Gateway RPC timeout 후 같은 mutating action을 새 ActionId로 재생성하지 않는다. 기존 ActionId 상태를 조회한다.
- `MAY_HAVE_EXECUTED` 이후 worker/transport 상태로 결과를 확정할 수 없으면 `OUTCOME_UNKNOWN`
- `OUTCOME_UNKNOWN`은 `retryable=false`
- idempotency mapping은 CreateSession/Action 모두 초기 24시간 보존한다. 이 보존 기간은 클라이언트/SDK의 최대 재시도 지평보다 길어야 하며, "정상 retry 중복 dispatch 0" 보장은 mapping의 보존과 coordination store 지속성 구성에 조건부다(§21.4).

## 15.10 Timeout 의미

다음 시간을 분리한다.

```text
HTTP synchronous wait budget
queue/admission deadline
approval deadline
browser execution deadline
artifact finalization deadline
session TTL/idle deadline
```

HTTP client disconnect나 `Prefer: wait` 만료는 browser action 자동 cancel을 의미하지 않는다.

Mutating action timeout 후 termination/quiescence를 입증하지 못하면 다음 mutating action을 시작하지 않는다. semantic state만 불확실하면 session은 `RECONCILIATION_REQUIRED`, protocol state까지 불확실하면 session/shard를 종료한다.

## 15.11 Action resolve와 reconciliation

`OUTCOME_UNKNOWN`으로 종료된 mutating action과 그로 인한 `RECONCILIATION_REQUIRED`는 자동으로 해소되지 않는다. 해소 경로는 session close와 명시적 resolve 두 가지뿐이다(D-28).

```http
POST /v1/sessions/{session_id}/actions/{action_id}/resolve
```

```json
{
  "resolution": "confirmed_executed",
  "basis": "post_read_verification",
  "note": "주문 내역 페이지에서 주문 번호 확인"
}
```

`resolution` 값:

```text
confirmed_executed       # caller가 재조회로 실행 사실을 확인함
confirmed_not_executed   # caller가 재조회로 미실행을 확인함
abandoned                # 검증 없이 진행을 선택했음을 기록
```

규칙:

- 대상 action이 `OUTCOME_UNKNOWN` 터미널 상태가 아니면 `409 action_resolution_invalid`.
- resolve는 caller의 **확정 기록**이다. 원칙적으로 agent server가 read/snapshot으로 페이지·외부 상태를 재확인한 뒤 호출한다. browserd는 ledger의 자체 outcome을 바꾸지 않고 resolution annotation(`resolved_as`, `resolved_by`, `resolved_at`, `basis`)을 추가한다(§9.5).
- resolve가 기록되면 해당 action이 유발한 `RECONCILIATION_REQUIRED`는 해제되고 session execution은 `IDLE`로 복귀한다.
- session이 이미 `FAILED`/`CLOSED`면 execution 전이는 없으며 annotation과 audit만 기록된다.
- `confirmed_not_executed`로 resolve해도 browserd가 원래 action을 자동 재실행하지 않는다. 재시도는 caller가 새 Idempotency-Key의 새 action으로 수행한다.
- `abandoned` 허용 여부는 tenant policy로 제어할 수 있다.
- resolve는 `browser:act` scope로 수행하고 audit event(§26.4)를 남긴다. 동일 resolution의 재호출은 idempotent하며, 다른 resolution으로의 재호출은 `409 action_resolution_invalid`다.

## 15.12 Event 전달

polling API(operation/session/action 조회)가 항상 상태의 source of truth다(D-30). event는 조회를 촉발하는 알림이며, SDK는 event 수신 시 해당 리소스를 GET으로 재조회하는 패턴을 기본으로 한다. 유실·중복·순서 역전은 모두 가능하다고 가정한다.

### Event 종류(초기)

```text
operation.state_changed
session.lifecycle_changed
session.execution_changed      # RECONCILIATION_REQUIRED 진입 포함
action.state_changed           # 터미널 상태, outcome_unknown 포함
action.approval_required
approval.decided
browser.control.changed
download.completed
artifact.state_changed
```

### 전달 채널

**Webhook (at-least-once)**

- tenant가 등록한 HTTPS endpoint로 전송한다. event는 PostgreSQL outbox에 기록한 뒤 백그라운드로 전달한다.
- 각 event는 `event_id`(UUIDv7)를 가지며 수신측이 멱등 처리한다.
- HMAC 서명 header와 timestamp를 포함하고, 수신측 replay window 검증을 문서화한다.
- bounded retry/backoff를 적용하고, 연속 실패 시 endpoint를 suspend하고 audit event를 남긴다. suspend 중의 event는 polling으로 조회할 수 있다.
- webhook 발신은 control plane에서 수행하며 shard egress와 **별개의 SSRF 정책**(loopback/사설/metadata IP 차단, redirect 재검증)을 적용한다. 대상 URL 등록/변경은 audit 대상이다.

**Event polling**

```http
GET /v1/events?cursor=...&limit=...
```

- `events:read` scope를 사용하며 tenant scope로 한정한다.
- event 보존 기간은 초기 24시간이다. cursor가 보존 범위를 벗어나면 명시적 gap 표시와 함께 최신 cursor를 반환한다.

Event payload에는 리소스 식별자와 새 상태 요약만 포함하고 secret/원문 URL 등 sensitive 값은 넣지 않는다(§26.3 redaction 규칙 준용).

# 16. Snapshot과 CUA 지원

## 16.1 Snapshot 형식

```json
{
  "type": "snapshot",
  "include": ["screenshot", "accessibility", "interactive_nodes"],
  "screenshot": {"format": "jpeg", "quality": 70, "delivery": "artifact"}
}
```

결과는 screenshot/DOM/accessibility가 완전한 동일 시점 transaction이라고 주장하지 않는다.

```json
{
  "snapshot_id": "snap_...",
  "captured_at": "...",
  "page_id": "pg_...",
  "session_incarnation": 1,
  "target_incarnation": 7,
  "document_epoch": 19,
  "url_revision": 25,
  "consistency": "near_consistent",
  "viewport": {
    "width": 1280,
    "height": 720,
    "device_scale_factor": 1
  },
  "frame_transform_id": "xf_...",
  "screenshot_artifact": {"id": "art_..."},
  "nodes": [
    {
      "node_ref": "node_...",
      "role": "button",
      "name": "로그인",
      "bounds": {"x": 1040, "y": 30, "width": 120, "height": 40},
      "states": ["focusable"]
    }
  ]
}
```

`screenshot.delivery=inline`이면 encoded bytes가 inline 한도(§12.4) 이하일 때 `screenshot_inline`(base64)로 응답에 직접 포함하고 artifact를 생성하지 않는다. 한도 초과 시 artifact로 자동 전환하고 `screenshot_inline_fallback=true`를 표시한다. snapshot 빈도가 높은 CUA loop에서 artifact 왕복 latency와 저장 churn을 줄이기 위한 옵션이다.

## 16.2 Snapshot consistency

페이지는 snapshot 생성 중에도 JavaScript로 변할 수 있다.

- screenshot과 accessibility/DOM capture 사이에 revision이 바뀌면 warning 또는 `consistency=changed_during_capture`
- policy에 따라 변화가 심하면 snapshot을 재시도할 수 있으나 bounded retry만 허용
- node action 시 snapshot/document epoch를 다시 확인
- stale snapshot이면 `409 snapshot_stale`

## 16.3 좌표 체계

- Skill point는 CSS viewport pixel 기준
- screenshot metadata에 viewport/device scale factor 포함
- viewer resize는 session viewport를 자동 변경하지 않음
- crop/scale 발생 시 viewer가 inverse transform을 적용
- human input은 `frame_transform_id`를 포함하며 stale transform input은 reject

## 16.4 CSS selector 지원 범위

v1 CSS selector는 best-effort primitive다.

제공:

- strict single selector resolve
- attached/visible 검사
- scroll into view
- 기본 hit-test/actionability
- bounded timeout wait

제공하지 않음:

- Playwright role/text locator 완전 호환
- 복잡한 automatic actionability retry semantics
- 모든 Shadow DOM 패턴 호환 보장

신뢰성이 필요한 Skill은 `snapshot → node_ref → action`을 우선 사용한다.

## 16.5 Snapshot/resource limit

Snapshot은 DOM/AX tree 크기로 worker memory/CPU를 공격할 수 있으므로:

- 최대 node 수: 3,000 초기
- node당 최대 string bytes: 4 KiB 초기
- 최대 result bytes: 4 MiB 초기
- 최대 snapshot generation time: 10초 초기
- ActionAdmission large-snapshot slot

을 적용한다. 초과 시 partial result를 자동 반환하지 않고 명시적 `snapshot_too_large` 또는 요청 profile에 정의된 truncation metadata를 반환한다.

# 17. PDF, Screenshot, Scrape

## 17.1 공통 원칙

- 각 기능은 compile-time `BrowserFeature`/typed action으로 구현
- 결과 binary는 artifact state machine을 통해 저장
- resource-heavy feature는 ActionAdmission을 통과
- 생성 전 크기를 가능한 범위에서 preflight하고 생성 중 byte quota를 적용
- browser effect/result와 artifact upload/finalization 상태를 구분

## 17.2 Screenshot

지원 옵션:

- PNG/JPEG/WebP 중 pinned Chromium에서 검증된 포맷
- viewport/full-page
- clip rectangle
- quality
- omit background

필수 제한:

```text
max dimensions
max pixel count
max encoded bytes
max capture time
```

Full-page 요청은 layout metrics로 크기를 preflight한다. limit을 넘는 경우 기본 reject한다. Tiling은 sticky/fixed element 의미가 달라질 수 있으므로 별도 feature/profile로 취급한다.

## 17.3 PDF

Chromium `printToPDF`를 사용한다.

지원 옵션:

- page size 또는 width/height
- margins
- landscape
- print background
- scale
- page ranges

PDF는 가능한 경우 stream transfer를 사용해 worker memory에 전체 base64 payload를 올리지 않고 object store에 chunk/multipart로 기록한다.

```text
printToPDF stream
 → bounded read chunk
 → artifact upload
 → byte limit 검사
 → finalize 또는 abort
```

Header/footer는 v1에서 arbitrary HTML template를 기본 허용하지 않고 제한된 placeholder schema를 권장한다.

```json
{
  "header": {"left": "", "center": "{title}", "right": "{pageNumber}/{totalPages}"}
}
```

## 17.4 Scrape

v1 scrape profile:

- raw HTML, bounded
- visible text
- metadata
- links
- accessibility snapshot
- 선택적 screenshot/PDF

Markdown/readability 변환은 Feature Module로 추가하되 input/output byte와 CPU deadline을 적용한다.

## 17.5 PDF URL 재-fetch 정책

브라우저가 이미 접근한 PDF URL을 별도 일반 HTTP client로 cookie와 함께 다시 가져오는 기능은 v1 기본 범위에서 제외한다.

- 브라우저가 download한 PDF는 normal download artifact로 처리
- 별도 fetch가 필요하면 `PolicyFetchClient`만 사용
- cookie forwarding 기본 false
- exact origin/policy/approval 필요
- 동일 mandatory egress와 redirect/IP 검증 적용

Feature Module이 임의 HTTP client로 network policy를 우회할 수 없어야 한다.

# 18. Viewer와 Human-in-the-loop

## 18.1 Viewer token / connection ticket

Viewer는 session API capability와 별도의 짧은 수명 credential을 사용한다.

Scope:

```text
viewer:read
viewer:control
viewer:admin
```

브라우저 WebSocket client에서 bearer token을 URL query에 직접 넣지 않는다. 권장 흐름:

```text
POST /v1/sessions/{session_id}/viewer-ticket
  → short-lived one-time ticket

WS /v1/sessions/{session_id}/viewer
Sec-WebSocket-Protocol: browser-viewer.v1
Cookie 또는 protocol handshake payload로 ticket consume
```

Ticket에는 tenant, session, session incarnation, scope, expiry, jti/nonce를 bind한다. WebSocket upgrade 시 `Origin`도 allowlist 검증한다.

## 18.2 Frame 전송

Chromium screencast를 사용할 수 있다. browserd는 Chromium ack를 각 viewer ack와 연결하지 않는다.

```text
Chromium frame
  → size/metadata validation
  → latest-frame shared slot
  → Chromium frame ack 즉시 전송
  → viewer broadcaster
      ├─ fast viewer
      ├─ slow viewer: old frame drop
      └─ disconnected viewer
```

- viewer당 queue는 latest 1~2 frame
- 느린 observer 때문에 Chromium이 stall하지 않아야 함
- 동일 page의 여러 observer는 가능한 범위에서 capture stream을 공유
- target/page 변경 시 transform epoch 갱신

Binary frame envelope 예:

```text
1 byte   message type
8 bytes  frame_id
8 bytes  transform_epoch
4 bytes  metadata_length
N bytes  JSON metadata
M bytes  JPEG payload
```

## 18.3 Client → Server message

```text
ack
ping
select_page
request_control
release_control
mouse
wheel
key
insert_text
composition_start
composition_update
composition_commit
composition_cancel
resize_view_only
```

모든 control input은 최소 다음을 포함한다.

```text
lease_epoch
input_sequence
page_id
frame_transform_id
```

## 18.4 Control 전환

- control acquire/release는 SessionExecutor를 통과한다.
- acquire가 승인되면 lease epoch를 증가시킨다.
- human control 중 agent mutating action은 기본 차단한다.
- agent server에 `browser.control.changed` event를 발행한다(전달 채널은 §15.12).
- disconnect/heartbeat timeout 후 agent control로 복귀한다.
- 강제 회수는 `viewer:admin`만 가능하다.
- 이전 lease epoch의 늦은 input은 폐기한다.
- 같은/작은 `input_sequence`는 replay로 폐기한다.

## 18.5 Input state cleanup

viewer disconnect/control release 시 다음을 best-effort reset한다.

- pressed mouse button
- pressed modifier/key state
- drag operation
- IME composition

cleanup 실패로 input 상태가 불확실하면 page/session snapshot을 요구하거나 session을 reconcile state로 둘 수 있다.

## 18.6 CJK IME

Viewer는 단순 keydown/keyup만 전달하지 않고 browser-side composition event를 수집한다.

```text
compositionstart
compositionupdate
compositionend
beforeinput/input
```

Worker는 pinned Chromium에서 검증된 CDP IME/text insertion primitive를 사용한다. 한글/일본어/중국어 조합 입력은 release gate에 포함한다.

## 18.7 Viewer는 sensitive capability

Viewer와 screenshot은 page-rendered secret을 볼 수 있다. `viewer:read`를 단순 observability 권한으로 취급하지 않고 sensitive data access scope로 본다.

# 19. Network egress와 SSRF 방어

Network security의 최종 invariant는 **Chromium이 proxy를 사용하도록 기대하는 것**이 아니라 **mandatory egress 이외 경로가 존재하지 않는 것**이다.

## 19.1 기본 구조

```text
Shard network namespace
│
├─ Chromium
│   ├─ Context A → route proxy port A
│   ├─ Context B → route proxy port B
│   └─ Context C → route proxy port C
│
└─ route/firewall
    └─ host-side egress ingress endpoint만 허용

Host / Egress Proxy
│
├─ source shard identity 확인
├─ destination listener/route → SessionId 매핑
├─ URL/scheme/host/port policy
├─ DNS resolve
├─ resolved IP 정책 검사
├─ 검증한 sockaddr로 직접 connect
├─ bandwidth/connection quota
└─ audit/usage
```

- Context proxy는 `proxyBypassList="<-loopback>"`를 사용한다.
- Chromium netns에는 public Internet, host loopback, 다른 shard subnet으로 직접 가는 route가 없다.
- Chrome-facing proxy URL의 credential에 의존하지 않는다.
- session route는 충분히 opaque하고 `(shard identity, route endpoint)`에 bind된다.
- session 종료/worker loss 시 route를 먼저 revoke한다.

Route identity의 신뢰 경계는 shard다. browser process가 compromise되면 같은 netns의 co-resident session route endpoint 사용을 네트워크 계층에서 구분할 수 없으므로, session 단위 network policy/quota/과금/감사 귀속은 shard 무결성에 조건부다(§3.3, §3.4). shard가 taint/compromise로 판정되면 동시간대 usage event에 diagnostic flag를 남긴다.

## 19.2 기본 scheme 정책

### Skill의 top-level navigation 허용

```text
http
https
```

### 페이지 내부 network 허용 가능

```text
http
https
ws
wss
```

### 기본 차단

```text
file:
chrome:
devtools:
filesystem:
javascript:
view-source:
intent:
custom scheme
```

`data:`/`blob:`은 page 내부 동작에는 허용할 수 있지만 외부 Skill이 직접 navigate할 목적지로는 기본 차단한다.

## 19.3 기본 IP 차단 대상

- loopback
- RFC1918 private
- link-local
- multicast/reserved
- carrier-grade NAT
- cloud metadata/known infrastructure ranges
- IPv6 unique-local/link-local
- 운영자가 지정한 host/service network

IPv4-mapped IPv6 등 canonical form으로 변환한 뒤 판단한다.

## 19.4 DNS/redirect/connect invariant

각 hop에서:

```text
1. URL canonicalize
2. scheme/host/port 검사
3. DNS/CNAME resolve
4. 모든 candidate IP canonicalize
5. IP policy 검사
6. 허용된 특정 sockaddr를 선택
7. 그 sockaddr에 직접 connect
8. hostname 의미 보존: CONNECT tunnel은 client TLS(SNI 포함)를 그대로 통과시키고, proxy가 직접 만드는 plain HTTP 요청은 Host header에 원 hostname을 유지
```

**검사 후 hostname을 다시 일반 resolver에 넘겨 재해석하지 않는다.**

Redirect가 발생하면 1부터 다시 수행한다. HTTPS(CONNECT)에서는 redirect가 TLS 내부에서 일어나 proxy에 보이지 않지만, 브라우저가 새 host로 여는 **새 CONNECT마다** 위 절차가 다시 적용되므로 hop 단위 재검증 invariant는 유지된다. proxy가 응답을 볼 수 있는 경로(plain HTTP, `PolicyFetchClient`)에서는 proxy가 redirect를 직접 1부터 재검증한다.

필수 canonicalization test:

- IPv4 integer/hex/octal 표현
- IPv4-mapped IPv6
- IPv6 zone identifier
- trailing dot
- IDNA/Punycode
- public/private mixed answer
- CNAME chain
- userinfo 포함 URL
- encoded host/port edge cases

## 19.5 WebSocket, QUIC, WebRTC

- WebSocket은 동일 proxy/network policy를 사용
- direct UDP/QUIC route 없음
- WebRTC non-proxied UDP/STUN/TURN도 netns/firewall에서 차단
- 새로운 Chromium protocol이 proxy를 사용하지 않더라도 route가 없으므로 우회할 수 없어야 함

## 19.6 Tenant network policy

예:

```text
public-web-default
allowlist-only
public-web-plus-approved-cidrs
no-download
```

`read-only-sites`처럼 HTTP 의미론을 강한 transport 보장으로 오해하게 만드는 이름은 사용하지 않는다. Method/path 제한이 필요하면 `semantic/safe-methods` policy로 분리하고 HTTPS visibility/브라우저 hook 의존성을 명시한다.

### Allowlist enforcement granularity

HTTPS(CONNECT tunnel)에서 mandatory proxy가 강제할 수 있는 단위는 **client가 선언한 CONNECT host:port와 resolve/검증된 IP**다. TLS 내부의 URL/path/method는 보이지 않는다. 따라서:

- `allowlist-only`의 실제 보장은 "선언 host가 allowlist에 있고, 그 host의 검증된 IP로만 연결된다"이다.
- 공유 CDN/공유 IP 환경에서는 allowlist된 host와 같은 IP를 쓰는 다른 vhost의 존재가 보장 강도를 낮춘다. 이 한계를 tenant 문서와 보장 문구에 명시한다.
- URL/path 수준 enforcement가 필요한 tenant에는 dedicated tier에서 certificate profile 기반 TLS inspection(명시적 MITM)을 별도 opt-in 기능으로 검토한다. shared tier에는 도입하지 않는다.

## 19.7 Upstream proxy

`shared_context/public`에서는 tenant가 지정한 arbitrary upstream proxy를 허용하지 않는다.

필요 시:

```text
browserd-managed regional egress
approved corporate proxy
private network class
customer dedicated worker/network class
```

으로 제공한다. browserd가 최종 connect 대상 IP를 검증할 수 없는 upstream proxy는 public-SSRF strong guarantee 대상에서 제외한다.

## 19.8 Network quota

Download event와 무관한 XHR/fetch/streaming DoS를 막기 위해 egress proxy에서 적용한다.

```text
max concurrent connections/session
connection creation rate
DNS query rate
egress bytes/sec
total egress bytes/session
idle connection timeout
optional response byte cap
```

# 20. Upload, Download, Artifact

## 20.1 Artifact namespace

논리 key는 항상 다음 scope를 포함한다.

```text
TenantId / SessionId / ArtifactId
```

사용자가 object path/local path를 지정할 수 없다.

## 20.2 Artifact state machine

```text
Upload:
UPLOADING → STORED → SCANNING ─┬→ AVAILABLE
                               ├→ QUARANTINED
                               └→ REJECTED

Generated:
GENERATING → FINALIZING ─┬→ AVAILABLE
                         └→ FAILED

AVAILABLE → DELETING → DELETED
```

State transition은 idempotent하고 artifact metadata에 checksum/size/content type source/origin을 기록한다.

## 20.3 Quota reservation

Artifact는 완료된 크기만 계산하지 않는다.

```text
1. action/upload 시작 전 reservation
2. generation/stream 중 actual bytes accounting
3. hard limit 초과 시 producer 중단
4. 성공 시 committed size로 전환
5. 실패 시 reservation release + partial cleanup
```

추적:

```text
committed artifact bytes/session
in-flight artifact bytes/session
worker temp bytes/inodes
object-store multipart bytes in flight
```

## 20.4 Upload

```http
POST /v1/sessions/{session_id}/artifacts/uploads
```

- MIME/extension/filename을 신뢰하지 않는다.
- filename은 display metadata일 뿐 path가 아니다.
- `set_files`에는 ArtifactId만 전달한다.
- materialize는 session private temp directory에서만 수행한다.
- symlink/hardlink/device node를 허용하지 않는다.
- page에는 명시된 artifact만 노출한다.
- malware scan은 policy hook으로 적용 가능하다.

## 20.5 Download

Browser download event는 frame/target registry를 통해 session에 귀속한다.

```text
downloadWillBegin(frame/guid)
 → frame→target→session lookup
 → guid→session binding 고정
 → session-specific download directory 확인
 → stream/size/quota tracking
```

- mapping되지 않는 download는 cancel + audit
- attribution 불명은 shard health degrade/taint 후보
- 최대 크기 초과 시 즉시 취소
- temp file은 session namespace에서만 존재
- local path/download URL을 API에 반환하지 않음
- 결과는 ArtifactId

## 20.6 Signed/download URL

- 짧은 expiry
- tenant/session/artifact scope
- fixed content disposition
- query secret log redaction

진짜 one-time/limited-use가 필요하면 일반 object-store presigned URL의 특성에 의존하지 않고 browserd의 stateful token-consume endpoint를 사용한다.

## 20.7 Janitor

Worker crash/object-store timeout 후 partial 상태를 정리하는 janitor를 둔다.

- orphan temp file
- abandoned multipart upload
- expired upload reservation
- failed quarantine object
- expired artifact

Janitor는 tenant namespace를 다시 검증하고 destructive cleanup을 idempotent하게 수행한다.

# 21. Persistence와 복구

## 21.1 기본 Session

v1 기본은 ephemeral BrowserContext다. Session 종료 시 context storage와 sandbox-local profile은 폐기한다.

## 21.2 Storage checkpoint 범위

v1 stable checkpoint:

- cookies
- 명시된 origin의 localStorage
- restore metadata와 Chromium artifact identity

experimental/후속:

- 일부 IndexedDB serializer
- sessionStorage 등 명시적 feature

비보장:

- service worker
- CacheStorage
- blob/browser cache
- extension state
- 열린 tab DOM/JS heap
- active network connection

Session 생성 요청의 `checkpoint_ref`(§15.2)로 restore를 지정한다. Checkpoint는 login credential과 동등한 민감 artifact로 취급한다.

- `checkpoint:create`/read scope 분리
- tenant/session ownership
- server-side encryption
- retention limit
- audit
- schema/browser compatibility metadata

## 21.3 Worker/Chromium 장애

- shard crash/worker loss 시 기존 live session은 `FAILED`
- in-flight mutating action은 known completion evidence가 없으면 `OUTCOME_UNKNOWN`
- action 자동 재실행 금지
- checkpoint restore는 opt-in일 수 있으나 **새 SessionId를 생성**
- 새 session은 `restored_from_checkpoint`, `recovered_from_session` metadata를 가질 수 있음
- 기존 PageId/NodeRef/Action pending state/control lease는 복원하지 않음

Worker loss 후 action 상태 확정은 다음 derivation rule을 따른다(D-33). ActionLedger는 worker-local이므로, gateway는 자신이 아는 전달 상태로 터미널 상태를 유도해 조회 가능한 mapping에 기록한다.

- gateway가 해당 action을 **전달 시도 전**이었거나 **전달 실패를 입증**할 수 있으면 `FAILED_KNOWN(not_dispatched)`. 새 Idempotency-Key의 새 action으로 재시도할 수 있다.
- 전달됐거나 전달 여부가 불확실하면 `OUTCOME_UNKNOWN(worker_lost)`.
- 이 결과는 worker-loss 처리(§28.4) 중 best-effort로 기록하며, 기록 전에 조회가 오더라도 동일 rule로 계산해 일관되게 응답한다.

## 21.4 Redis 장애

Live worker는 이미 소유한 Session을 계속 처리할 수 있다. Gateway는 최근 route cache를 제한적으로 사용할 수 있다.

Redis degraded mode:

```text
- 신규 Session 생성/placement는 기본 중단
- 기존 cached route만 TTL 내 사용 가능
- worker_epoch/placement_version 검증 필수
- cache lease expiry 후 fail closed
- 다른 worker로 추측 reroute 금지
- capability revocation freshness가 보장되지 않는 scope는 fail closed 가능
```

복구 후 worker는 현재 owned session directory를 fenced registration protocol로 재등록한다.

coordination store 데이터가 완전히 유실되면 보존 기간 내 idempotency mapping도 함께 사라져 동일 key 재시도가 중복 operation을 만들 수 있다. 유실 구간의 신규 생성 중단(fail closed)이 이 위험을 함께 줄이며, idempotency/directory key space에는 지속성 구성(replication 등)을 권장한다.

## 21.5 Object store 장애

- browser action 자체와 artifact finalization 결과를 분리
- screenshot/PDF처럼 artifact가 action 결과의 본체면 store 실패는 action failure로 보고 partial object 정리
- download가 이미 외부 side effect를 일으킨 뒤 store 실패한 경우 known browser effect + artifact failure를 별도 field로 표현
- object store 장애가 무제한 worker temp accumulation으로 이어지지 않게 temp/in-flight quota 적용

## 21.6 PostgreSQL 장애

- capability/JWT 검증은 서명 기반이므로 PostgreSQL 없이 동작한다. revocation freshness는 Redis 경로다.
- Gateway는 tenant plan/policy/network policy를 TTL 캐시로 보유한다. 캐시가 유효한 tenant는 기존 동작을 유지한다.
- 캐시 미보유/만료 tenant의 신규 session 생성은 fail closed한다. 이미 발급된 policy snapshot으로 동작 중인 live session은 계속 동작한다.
- usage event/audit index 기록은 bounded local spool 후 재전송한다. spool 상한 초과 시 §26.5와 동일한 fail-closed 정책을 적용한다.
- emergency deny 배포는 Redis/coordination 경로이므로 PostgreSQL 장애와 독립적으로 동작해야 한다.

# 22. Feature Module 구조

## 22.1 원칙

동적 native plugin 대신 compile-time registry를 사용한다. Feature는 trusted code이지만 실수로 security/resource boundary를 우회할 수 있으므로 raw capability를 최소화한다.

## 22.2 Manifest

```rust
struct FeatureManifest {
    name: &'static str,
    version: &'static str,
    required_scopes: &'static [Scope],
    dependencies: &'static [&'static str],
    hook_order: i32,
    process_compatibility_fingerprint: Option<Hash>,
    resource_requirements: FeatureResourceRequest,
    failure_policy: FeatureFailurePolicy,
}

enum FeatureFailurePolicy {
    RejectAction,
    FailSession,
    TaintShard,
    BestEffortAudit,
}
```

Trait에서 native `async fn` dyn-dispatch 구현 방식은 실제 Rust stable/toolchain에 맞춰 boxed future, `async_trait`, enum/static dispatch 중 하나로 고정한다.

## 22.3 Hook

```text
on_context_created
on_target_attached
on_target_ready
on_frame_navigated
before_action
after_browser_effect
after_action
on_download_started
on_control_changed
on_session_closing
```

Hook ordering과 timeout을 명시한다. post-hook 실패가 이미 발생한 browser side effect를 없었던 것으로 만들면 안 된다.

## 22.4 제한된 내부 capability

Feature에 기본적으로 제공하지 않음:

```text
raw CDP transport
BrowserHandle
arbitrary filesystem path
raw object-store client
arbitrary outbound HTTP client
```

대신:

```text
TargetCommands
ArtifactWriter
PolicyFetchClient
SessionTempFile
AuditEmitter
ActionAdmissionHandle
```

처럼 policy/resource wrapper를 제공한다.

## 22.5 Built-in feature

```text
core-navigation
core-input
snapshot
screenshot
pdf
scrape
viewer
human-control
uploads
downloads
checkpoint
network-policy
audit
privileged-evaluate
```

## 22.6 Chrome extension과 구분

`BrowserFeature`는 server-side Rust module이다. Chrome extension은 process-level CompatibilityKey 일부다.

- `shared_context`: Chrome extension 금지
- `tenant_dedicated_shard`: 운영자 승인 bundle 가능
- `dedicated_process/worker`: 승인 bundle 가능

Shared shard 지원을 향후 추가하려면 extension별 incognito/storage/background-state certification이 필요하다.

## 22.7 Steel 코드 활용 정책

Steel 또는 다른 Apache/MIT 계열 구현을 참고/포팅할 경우:

1. 실제 소스/dependency 라이선스를 포팅 시점에 재검증
2. 원본 copyright/license header 유지
3. 변경·출처를 `THIRD_PARTY_NOTICES` 기록
4. behavior test를 먼저 작성
5. 기존 singleton/session 구조를 그대로 가져오지 않음
6. API 호환보다 edge case/behavior 참고를 우선

# 23. 인증과 권한

## 23.1 외부 인증

권장 구조:

```text
Agent Server ── mTLS ── Browser Gateway
                  +
            short-lived JWT
```

JWT 예:

```json
{
  "iss": "browser-auth",
  "sub": "principal-id",
  "tenant_id": "tenant-id",
  "aud": "browserd",
  "scopes": ["session:create", "browser:act", "artifact:read"],
  "cnf": {"x5t#S256": "client-cert-thumbprint"},
  "jti": "...",
  "nbf": 1780000000,
  "exp": 1780000300
}
```

검증:

- exact issuer/audience
- algorithm allowlist
- key id/rotation
- exp/nbf clock skew
- mTLS actor binding이 사용되는 profile이면 `cnf` 일치
- tenant/principal/scope
- revocation/jti policy

## 23.2 Session capability

Session 생성 후 session-specific short capability를 발급할 수 있다.

```text
session_id
tenant_id
principal_id
session_incarnation
scopes
policy_snapshot_id
expiry
jti
optional actor binding
```

Capability는 bearer secret이다. `nonce`가 들어 있다는 사실만으로 replay-safe라고 주장하지 않는다. one-time 의미가 필요한 capability는 server-side consume state를 사용한다.

LLM prompt/context에는 raw capability를 넣지 않고 Skill Host가 보관하는 logical session handle을 권장한다.

## 23.3 권한 예시

```text
session:create
session:read
session:close
browser:act
browser:evaluate
browser:storage:read
viewer:read
viewer:control
artifact:upload
artifact:read
checkpoint:create
checkpoint:read
secret:use
approval:read
approval:read_context
approval:decide
events:read
admin:force-close
admin:force-control
```

`browser:evaluate`, storage read, viewer read, checkpoint read, `secret:use`, `approval:read_context`는 sensitive/privileged scope다.

## 23.4 Secret handling

- proxy/login credential은 secret reference로 전달
- secret value를 API response, trace, error, metric label에 넣지 않음
- origin-bound credential fill은 현재 origin/document를 재검증 후 실행
- secret이 포함된 action payload는 audit에 원문 저장하지 않음
- worker memory에 secret을 필요한 최소 시간만 유지
- viewer masking은 UI best-effort이며 security guarantee가 아님
- screenshot/PDF/page DOM이 secret을 포함하지 않는다고 보장하지 않음

## 23.5 Policy snapshot과 emergency deny

Session 생성 시 일반 policy는 immutable snapshot으로 고정할 수 있다.

```text
normal plan/quota
feature profile
isolation
network allowlist
TTL
```

다음은 즉시성이 필요한 mutable emergency deny로 별도 관리한다.

```text
tenant/session disabled
domain/IP emergency deny
secret revoked
feature kill switch
Chromium build kill switch
force_dedicated_process
```

# 24. Action policy와 사용자 승인

LLM은 prompt injection 영향을 받을 수 있으므로 Skill 호출 자체를 사용자 승인으로 간주하지 않는다.

Policy hook 결과:

```text
allow
deny
require_external_approval
```

Policy engine에 제공:

- tenant/session/principal
- session incarnation/policy snapshot
- current origin + URL revision
- action type
- target node role/name의 제한된 metadata
- document/frame epoch
- credential 사용 여부
- upload/download 여부
- navigation destination
- privileged evaluate 여부

## 24.1 CanonicalActionProposal

승인은 추상적인 “이 세션의 클릭”이 아니라 exact proposal에 bind한다.

```rust
struct CanonicalActionProposal {
    session_id: SessionId,
    session_incarnation: u64,
    page_id: PageId,
    target_incarnation: u64,
    frame_document_epoch: u64,
    current_origin: Origin,
    url_revision: u64,
    action_type: ActionType,
    canonical_arguments_hash: Hash,
    node_ref: Option<NodeRef>,
    credential_refs_hash: Hash,
    expires_at: DateTime<Utc>,
}
```

Approval token binding:

```text
proposal_hash
tenant_id
principal_id
session_id
session_incarnation
one-time jti
expiry
```

## 24.2 실행 직전 TOCTOU 재검증

Approval 이후 실제 dispatch 전에:

- session incarnation 동일
- placement ownership 유효
- document/frame epoch 동일
- current origin/url revision 정책상 허용
- node_ref/action target 유효
- network/policy emergency deny 재평가
- approval token 미사용/미만료

하나라도 바뀌면 기존 approval을 재사용하지 않고 `approval_stale`로 종료한다.

## 24.3 Approval state

`require_external_approval`이면 Action은 `PENDING_APPROVAL`이며 execution timeout과 별도의 approval deadline을 사용한다.

- approval 이전 cancel은 known-safe
- approval token은 기본 one-time
- human control 전환 중 pending approval을 자동 실행하지 않음
- session document/origin 변경 시 pending proposal invalidation 가능

## 24.4 Approval API

`require_external_approval` action의 승인 주체는 Skill 호출자가 아니라 별도 approval principal이다.

```http
GET  /v1/approvals?state=pending&session_id=...
GET  /v1/approvals/{approval_id}
POST /v1/approvals/{approval_id}/decision
```

```json
{ "decision": "approve", "reason": "..." }
```

- 조회는 `approval:read`, 결정은 `approval:decide` scope를 사용한다. 요청 당사자 principal이 스스로 승인하는 것을 policy로 금지할 수 있다(4-eyes).
- 조회 응답은 CanonicalActionProposal의 사람이 읽을 수 있는 요약(action type, 현재 origin, target node role/name, credential 사용 여부, 만료)을 포함한다.
- 승인 화면용 컨텍스트 스크린샷은 선택 기능이다. proposal 생성 시점의 page screenshot을 artifact로 첨부할 수 있으나, 이는 viewer read와 동등한 sensitive data access이므로 `approval:read`에 자동 포함하지 않고 별도 policy + `approval:read_context` scope로 제어한다.
- decision은 one-time이다. approve 시 서버가 내부 approval token을 consume 상태로 만들고 §24.2의 TOCTOU 재검증을 거쳐 dispatch한다.
- deny 또는 approval deadline 만료 시 action은 `FAILED_KNOWN(approval_denied|approval_timeout)`으로 종료한다.
- pending 알림은 §15.12의 `action.approval_required` event로 전달할 수 있다.

# 25. 오류 모델

## 25.1 오류 응답

```json
{
  "error": {
    "code": "session_controlled_by_human",
    "message": "The session is currently controlled by a human viewer.",
    "retryable": true,
    "details": {},
    "trace_id": "..."
  }
}
```

`retryable=true`는 **같은 logical operation/action을 안전하게 다시 조회/재시도할 수 있음**을 의미한다. mutating action의 `OUTCOME_UNKNOWN`에는 절대 사용하지 않는다.

## 25.2 주요 오류 코드

| Code | HTTP | Retry | 의미 |
|---|---:|---:|---|
| invalid_request | 400 | N | schema/argument 오류 |
| unauthenticated | 401 | 조건부 | 인증 실패 |
| permission_denied | 403 | N | scope/policy 거부 |
| session_not_found | 404 | N | session 없음 또는 tenant 불일치 |
| operation_not_found | 404 | N | operation 없음 |
| page_not_found | 404 | N | page 없음 |
| stale_node_ref | 409 | Y/read | 오래된 node handle |
| stale_document_ref | 409 | Y/read | frame/document epoch 불일치 |
| snapshot_stale | 409 | Y/read | snapshot 이후 page revision 변경 |
| generation_mismatch | 412 | N | `if_session_incarnation` precondition 실패 |
| placement_mismatch | 409/503 | Y/status | worker epoch/placement fencing 실패 |
| idempotency_conflict | 409 | N | 동일 key에 다른 request |
| approval_stale | 409 | N | 승인 proposal과 현재 page/policy 상태가 다름 |
| session_controlled_by_human | 423 | Y | human control 중 |
| reconciliation_required | 409 | N/mutate | 이전 mutating action의 semantic outcome 확인 필요 |
| action_resolution_invalid | 409 | N | resolve 대상 action의 상태가 유효하지 않거나 다른 resolution이 이미 기록됨 |
| action_outcome_unknown | 200 | **N** | 오류 envelope가 아니라 action 터미널 상태로 반환. 표 아래 설명 참조 |
| action_timeout | 504 | 조건부 | known timeout; uncertainty 여부는 action status로 구분 |
| action_admission_timeout | 503 | Y | resource-heavy action 실행 slot 확보 실패 |
| tenant_quota_exceeded | 429 | Y | tenant quota 초과 |
| rate_limited | 429 | Y | API rate limit |
| network_policy_denied | 403 | N | SSRF/allowlist 정책 거부 |
| network_budget_exceeded | 429 | 정책 | connection/byte budget 초과 |
| artifact_too_large | 413 | N | artifact/file limit 초과 |
| snapshot_too_large | 413 | N | snapshot DOM/result limit 초과 |
| target_limit_exceeded | 429 | 조건부 | target/frame/worker limit 초과 |
| queue_timeout | 503 | Y | CreateSession operation queue deadline |
| global_capacity_exceeded | 503 | Y | global/host capacity 없음 |
| browser_start_failed | 503 | Y | Chromium/sandbox 시작 실패 |
| context_create_failed | 503 | Y | context 생성 실패 |
| target_bootstrap_failed | 503 | 조건부 | primary/required target 초기화 실패 |
| browser_crashed | 503 | N/live | shard crash |
| worker_lost | 503 | N/live | worker ownership 상실 |
| worker_unavailable | 503 | Y/status | routing/RPC 실패 |
| session_expired | 410 | N | TTL 만료 |
| audit_unavailable | 503 | Y | fail-closed audit action을 안전하게 기록 불가 |
| internal | 500 | 조건부 | 내부 오류 |

`OUTCOME_UNKNOWN`은 transport 오류가 아니라 action의 터미널 상태다. 동기 POST 응답과 GET 조회 모두 HTTP `200` + `status=outcome_unknown`으로 표현하고 5xx를 사용하지 않는다. 범용 client/proxy의 5xx 자동 재시도 관행이 "unknown은 재시도 불가" 원칙과 충돌하는 것을 피하기 위해서다. 같은 Idempotency-Key 재전송은 기존 ActionId로 dedup되므로 상위 재시도 미들웨어가 있어도 중복 dispatch로 이어지지는 않는다. 해당 응답에는 반드시 기존 `action_id`를 포함한다.

`approval_required`는 오류가 아니라 `202 Accepted` + `PENDING_APPROVAL` action 상태로 표현하며(§24.3), 오류 코드 표에 두지 않는다.

내부 path, raw CDP payload, secret, stack trace는 외부 오류에 포함하지 않는다.

## 25.3 오류와 browser effect 분리

Feature/action 응답은 필요 시 다음을 별도 표현한다.

```text
browser_effect_status
artifact_status
audit_status
```

예를 들어 click이 성공한 뒤 audit sink 전송이 지연됐다고 click 자체를 `failed`로 되돌려 외부에 재시도를 유도하면 안 된다.

# 26. Observability

## 26.1 Metrics

고카디널리티 tenant/session/action ID를 metric label로 사용하지 않는다. Tenant별 사용량은 usage event/DB에서 집계한다.

### Fleet/Shard

```text
browserd_workers_ready
browserd_shards_by_lifecycle{profile}
browserd_shards_by_health{reason}
browserd_shard_memory_current_bytes
browserd_shard_memory_peak_bytes
browserd_shard_cpu_ratio
browserd_shard_memory_pressure_ratio
browserd_shard_contexts
browserd_shard_targets
browserd_shard_age_seconds
browserd_shard_recycles_total{reason}
browserd_browser_crashes_total{reason}
browserd_cgroup_oom_group_kills_total
browserd_cgroup_pids_max_events_total
browserd_orphan_cleanup_total{result}
browserd_warm_pool_shards
```

### Session/Operation

```text
browserd_operations_by_state{type,state}
browserd_sessions_by_lifecycle{isolation}
browserd_session_create_duration_seconds{isolation}
browserd_session_duration_seconds{isolation}
browserd_session_failures_total{reason,isolation}
browserd_queue_depth{plan,workload_class}
browserd_queue_wait_seconds{plan,workload_class}
browserd_worker_reservations{state}
browserd_session_cold_creates_total{isolation}
```

### Target/CDP

```text
browserd_targets_by_type{type}
browserd_target_bootstrap_duration_seconds{type}
browserd_target_bootstrap_failures_total{type,reason}
browserd_unmapped_targets_total{type}
browserd_cdp_pending_commands
browserd_cdp_event_queue_depth
browserd_cdp_oversized_messages_total
browserd_cdp_late_responses_total
```

### Action

```text
browserd_actions_total{type,status}
browserd_action_duration_seconds{type}
browserd_action_queue_wait_seconds{type}
browserd_action_admission_wait_seconds{class}
browserd_actions_outcome_unknown_total{type,reason}
browserd_sessions_reconciliation_required
browserd_idempotency_hits_total{type}
browserd_actions_resolved_total{resolution}
```

### Viewer/Artifact/Network

```text
browserd_viewers_connected{mode}
browserd_viewer_frame_latency_seconds
browserd_viewer_frames_dropped_total
browserd_control_stale_inputs_total{reason}
browserd_artifact_bytes_total{type}
browserd_artifact_bytes_inflight{type}
browserd_downloads_blocked_total{reason}
browserd_unmapped_downloads_total
browserd_network_denied_total{reason}
browserd_network_connections_active{network_class}
browserd_egress_bytes_total{network_class,result}
browserd_egress_route_revocations_total{reason}
browserd_event_outbox_depth
browserd_event_deliveries_total{result}
```

## 26.2 Trace

Action trace 예:

```text
HTTP request
└─ auth/capability
└─ session route + fencing
└─ SessionExecutor queue wait
└─ policy / approval
└─ ActionAdmission(optional)
└─ dispatch intent
└─ CDP/feature operation
└─ target/page lifecycle correlation
└─ artifact finalize(optional)
└─ audit WAL append/emit
```

## 26.3 Structured log

필수 field 예:

```text
trace_id
request_id
tenant_id 또는 privacy-preserving tenant diagnostic key
principal_id
operation_id
session_id
session_incarnation
worker_id
worker_epoch
shard_id
placement_version
action_id
event
status
latency_ms
```

### URL/secret redaction

기본 로그에 full URL을 남기지 않는다.

```text
scheme
host 또는 registrable-domain/hash
port
path template/hash
query omitted
fragment omitted
userinfo omitted
```

cookie, form value, authorization, secret reference resolved value는 원문 금지다.

## 26.4 Audit event

- operation/session create/close/fail
- effective isolation/network class 선택
- viewer ticket/token 발급
- control acquire/release/force/expiry
- credential injection
- upload/download/checkpoint
- privileged evaluate
- network policy denial
- approval proposal/approval/denial/stale
- action resolve(reconciliation) 기록
- admin force-close
- shard taint/security kill
- runtime isolation kill switch 변경
- tenant isolation auto-escalation 적용/해제

## 26.5 Audit WAL

외부 immutable audit sink가 잠시 실패해도 critical event를 잃지 않도록 bounded local durable spool/WAL을 둘 수 있다.

Critical action의 정책 예:

```text
local audit intent durable append
 → browser dispatch
 → outcome append
 → background immutable sink delivery
```

WAL이 가득 차면 credential injection, approval-required action, upload/download, admin/control action 등은 fail closed한다. 단순 low-risk read action의 degraded policy는 별도로 정할 수 있다.

# 27. Usage와 과금 계측

v1 usage event:

```text
session_wall_seconds
browser_weighted_seconds
action_count_by_type
action_resource_class_seconds
egress_bytes
ingress_bytes
artifact_storage_byte_seconds
artifact_bytes_generated
viewer_seconds
viewer_egress_bytes
pdf_pages 또는 pdf_action_count
```

Usage event는 unique event ID를 가지며 at-least-once 전송한다. 집계기는 event ID로 멱등 처리한다.

`browser_weighted_seconds`와 action resource usage는 requested class가 아니라 server가 계산한 effective isolation/workload/resource class를 사용한다.

Tenant별 상세 과금 차원은 Prometheus metric label이 아니라 usage event store에서 관리한다.

# 28. Multi-node routing과 HA

## 28.1 Worker registration / ownership

Worker는 stable `worker_id`와 process 시작마다 증가/변경되는 `worker_epoch`을 가진다.

주기 등록:

```text
worker_id
worker_epoch
region
version
compatibility keys
sandbox capability
network classes
ready shard count
reserved/free resource vector
queue/reservation depth
health timestamp
ownership lease expiry
```

`worker_epoch`은 단조성이 유지되어야 fencing이 성립한다. worker는 local durable counter로 epoch을 보존하거나 directory가 발급·검증하는 epoch을 사용하며, coordination store 데이터 유실 후에도 이전보다 작은 epoch으로 재등록될 수 없어야 한다.

## 28.2 Session directory와 fencing

```text
session_id →
  worker_id,
  worker_epoch,
  shard_id,
  placement_version,
  session_incarnation,
  lifecycle,
  lease_expires_at
```

Gateway는 모든 session RPC에 다음 fencing 값을 전달한다.

```text
worker_epoch
placement_version
session_incarnation
```

Worker는 하나라도 현재 ownership과 다르면 실행하지 않는다.

Directory의 worker ownership 항목이 **Directory Lease**다. host-local Supervisor Lease(§13.4)와 별개이며, TTL 관계는 D-32(`supervisor_lease_ttl ≤ directory_lease_ttl`)를 따른다.

## 28.3 Multi-gateway scheduling

여러 Gateway가 동일 worker capacity를 중복 소비하지 않도록:

- CreateSession queue는 region별 logical owner가 소비하거나
- reservation backend에서 OperationId/resource allocation을 원자화한다.

Worker reservation이 최종 capacity linearization point다.

## 28.4 Worker loss

Heartbeat/ownership lease expiry 후:

```text
1. 해당 worker로 신규 routing 중지
2. shard egress route revoke
3. sandbox supervisor가 owned shard cgroup kill
4. directory placement LOST/failure 기록
5. live Session → FAILED(worker_lost)
6. in-flight MAY_HAVE_EXECUTED action → OUTCOME_UNKNOWN
7. §21.3 derivation rule에 따라 action 터미널 상태를 조회 가능한 mapping에 기록(best-effort)
```

동일 worker_id의 새 process/epoch가 이전 session을 소유한다고 간주하지 않는다.

## 28.5 Redis 장애

- 신규 placement/reservation은 기본 fail closed
- cached existing route는 짧은 TTL 동안 사용할 수 있음
- worker fencing 검증 필수
- cache lease 만료 후 기존 action도 fail closed
- 다른 worker로 추측 reroute하지 않음

## 28.6 Rolling deployment

1. worker `admission=CLOSED`, lifecycle drain 표시
2. 신규 reservation/session 배정 중지
3. 기존 session 자연 종료 대기
4. grace 초과 시 tenant/policy에 따라 close
5. shard cleanup 후 worker 교체

“새 session admission 무중단” 보장은 다음 전제에서만 한다.

- 최소 하나 이상의 다른 compatible worker 존재
- drain worker 부하를 제외해도 SLA를 만족하는 spare capacity 존재
- Gateway/Worker protocol minor compatibility 유지

Single-node에서는 이 조건이 없으면 짧은 create pause가 허용된다.

## 28.7 Failure domain

```text
BrowserShard:
  Chromium crash/resource/security blast radius

Worker:
  control-plane blast radius; worker 소유 모든 session 영향 가능

Host:
  kernel/network/storage blast radius
```

한 worker process가 소유하는 shard/session 수도 상한을 둔다.

# 29. 데이터 저장

## 29.1 PostgreSQL

지속 데이터:

- tenant
- plan/quota
- API key/service account
- network policy/network class configuration
- feature/isolation policy
- Chromium rollout metadata
- audit index
- usage aggregate
- artifact metadata
- checkpoint metadata
- webhook endpoint 설정과 event outbox/delivery 상태

Live browser state나 exact target/page registry는 저장하지 않는다.

## 29.2 Redis/coordination store

휘발/coordination 데이터:

- session directory + fencing metadata
- worker heartbeat/ownership lease
- CreateSessionOperation state/queue metadata
- worker reservation metadata
- create/action idempotency mapping
- action terminal-state mapping(worker-loss derivation 결과 포함)
- short-lived capability/revocation state
- viewer ticket consume state
- rate limit bucket
- emergency kill-switch cache/distribution metadata

Redis가 source of truth인 live Chromium state는 없다.

## 29.3 Worker-local durable state

필요 시 local WAL/spool:

- critical audit intent/outcome
- bounded artifact multipart cleanup metadata
- shutdown/ownership cleanup state

Action external side effect를 exactly-once로 만들기 위해 local DB를 사용하는 것으로 오해하지 않는다. Host/worker loss 시 in-flight mutating action은 여전히 `OUTCOME_UNKNOWN`일 수 있다.

## 29.4 Object storage

- screenshot
- PDF
- upload/download
- checkpoint
- optional diagnostic artifact

모든 object는 tenant/session namespace, server-side encryption, lifecycle/retention policy를 사용한다.

# 30. Chromium/CDP 업그레이드 정책

## 30.1 Compatibility artifact

Worker image에 단순 Chromium version string만 고정하지 않는다.

```text
ChromiumArtifactIdentity
- binary digest
- product version
- Chromium revision
- browser protocol schema digest
- JS protocol schema digest
- launch profile digest
- extension bundle digest
- font bundle digest
- certificate/runtime bundle digest
```

## 30.2 Worker readiness self-test

Worker가 production admission을 열기 전에 pinned Chromium을 실제 실행해 최소 다음 behavior probe를 통과한다.

```text
- Browser version/revision expected match
- Chromium sandbox 활성
- outer sandbox contract 확인
- BrowserContext create/dispose
- per-context proxy + <-loopback>
- mandatory egress/direct-route denial
- target auto-attach/pause/resume
- browserContext ownership attribution
- locale/timezone/UA/device emulation
- context download behavior
- printToPDF streaming mode, 지원 시
- screencast frame/ack
- context cleanup 후 orphan target 0
```

Protocol method가 schema에 존재하는지만 확인하지 않고 실제 behavior를 검사한다.

## 30.3 Rollout

- runtime 자동 update 금지
- compatibility/integration/security/load tests
- canary worker pool
- crash/action failure/target bootstrap/memory/screenshot diff 비교
- 문제가 생기면 신규 admission 중지 후 이전 artifact로 rollback
- severe shared-context regression이면 artifact rollback 전에 `force_dedicated_process` kill switch 가능
- 오래된 worker는 drain 후 교체

브라우저 security update는 일반 backend dependency보다 높은 priority로 취급하되 compatibility gate를 생략하지 않는다.

# 31. 테스트 전략

## 31.1 Unit/Property test

- 각 독립 state axis transition
- operation cancellation/idempotency
- session/action idempotency
- `MAY_HAVE_EXECUTED`/`OUTCOME_UNKNOWN` invariants
- quota/DRR fairness
- worker reservation uniqueness/expiry
- capability/JWT/fencing validation
- URL canonicalization/IP policy
- node/frame/document epoch validation
- control lease/input sequence
- artifact state/quota reservation
- scheduler/resource envelope

주요 invariant:

```text
한 SessionId placement는 동시에 두 worker epoch에서 active일 수 없다.
DRAINING/admission-closed shard에는 신규 session을 commit하지 않는다.
새 target은 TargetManager bootstrap 전에 run하지 않는다.
CLOSED/FAILED session에 새 mutating action을 dispatch하지 않는다.
MAY_HAVE_EXECUTED 이후 unknown action을 자동 replay하지 않는다.
RECONCILIATION_REQUIRED session에 새 mutating action을 실행하지 않는다.
다른 tenant/session artifact handle을 resolve할 수 없다.
worker ownership lease 상실 후 shard egress가 유지되지 않는다.
RECONCILIATION_REQUIRED는 resolve(§15.11) 또는 close로만 해제된다.
supervisor lease TTL은 directory lease TTL을 초과하지 않는다.
```

## 31.2 Chromium integration matrix

- cookie/localStorage/permission/storage context isolation
- per-context proxy route
- popup/OOPIF/worker/service-worker bootstrap
- page/frame/target limit
- locale/timezone/UA/device 적용 before-run
- screenshot/PDF stream
- node_ref iframe navigation stale handling
- download frame→session attribution
- context dispose 후 target/download 잔존 여부
- viewer control/IME
- renderer/browser crash propagation

## 31.3 Security test

- session IDOR/capability scope
- stale/replayed capability/viewer ticket
- raw target/context ID leakage
- host/other-shard filesystem/socket access
- `file:`/custom scheme navigation
- localhost/private/metadata SSRF
- implicit loopback proxy bypass
- redirect SSRF
- DNS rebinding
- IPv4/IPv6 canonicalization tricks
- mixed public/private DNS answer
- WebSocket/QUIC/WebRTC bypass
- upstream proxy policy
- artifact path/symlink traversal
- ZIP bomb/large upload/download
- secret/log redaction
- malformed/oversized CDP/viewer payload
- cross-shard proxy route 사용
- approval TOCTOU/replay
- approval decision replay/자기승인(4-eyes) 정책
- webhook 대상 URL의 사설/loopback/metadata IP·redirect 정책

## 31.4 Action uncertainty fault injection

모든 mutating action에 대해 fault point를 주입한다.

```text
before ledger accept
after accept/before queue
after policy/before dispatch intent
after dispatch intent/before CDP write
after CDP write/before response
after browser response/before gateway response
```

검증:

- known pre-dispatch crash는 재실행 가능 상태 또는 known cancel
- possible dispatch 이후 증명 불가 시 OUTCOME_UNKNOWN
- gateway RPC timeout이 새로운 ActionId click으로 변하지 않음
- timeout/quiescence 전 다음 mutating action이 시작되지 않음

## 31.5 Chaos test

- Chromium SIGKILL/renderer crash
- worker SIGKILL/SIGSTOP
- sandbox supervisor restart
- gateway restart
- Redis partition
- PostgreSQL 장애
- object store partial multipart timeout
- egress proxy half-open/DNS stall
- audit sink failure/WAL full
- cgroup OOM/PID exhaustion
- disk bytes/inode full
- target/event flood
- host network route revoke

Worker SIGKILL test의 핵심 acceptance:

```text
ownership lease expiry 후
- owned Chromium process 0
- egress route 0
- session LOST/FAILED 일관성
```

## 31.6 Load/Soak test

benchmark matrix:

```text
contexts/shard: 1 / 4 / 8 / 16
workload: light / interactive / heavy
viewer: off / 1 / 4 observers
pages: 1 / 4 / 8
target storm: normal / worker-heavy / iframe-heavy
network: low / sustained stream
feature: screenshot / PDF / mixed
```

수집:

- warm/cold create p50/p95/p99
- memory.current/context 및 target
- memory leak slope
- PSI/CPU/action
- crash/taint/cleanup rate
- target bootstrap latency/failure
- viewer latency/drop
- action admission wait
- throughput/worker

`max_contexts_per_shard=8`은 결과에 따라 확정한다.

Soak는 최소 72시간 mixed workload를 권장하고 browser recycle을 포함한다. 단순 RSS 증가가 아니라 warm-up 이후 `memory.current` 추세, contexts-created 대비 leak slope, recycle 전후 baseline을 본다.

## 31.7 Upgrade compatibility test

- BrowserContext isolation regression
- CDP behavior probe
- checkpoint stable subset restore
- API schema backward compatibility
- worker/gateway minor protocol negotiation
- artifact metadata migration
- 이전 build 대비 memory/crash/target bootstrap regression

# 32. 구현 단계와 검증 게이트

보안 substrate와 target lifecycle을 뒤 단계에 붙이지 않는다. Shared-context의 성립 여부를 먼저 검증하고 그 위에 기능을 올린다.

## Phase -1 — Architecture spike

구현/검증 prototype:

- pinned Chromium에서 per-context proxy route
- `<-loopback>`과 netns direct-route denial
- popup/OOPIF/worker/service-worker pause-before-run bootstrap
- Context dispose 후 target/download cleanup
- screencast + input + CJK IME
- Chromium sandbox가 outer namespace 안에서도 정상 활성화
- browser-level proxy flag 유무에 따른 per-context proxyServer 실제 적용(플랫폼별 quirk 확인)
- service worker 발 요청의 per-context proxy route 귀속
- BFCache 비활성 플래그의 실효성(back/forward가 항상 새 문서 로드를 유발하는지)

### Gate

다음이 불안정하면 production shared-context를 열지 않는다.

```text
- target before-run bootstrap 불가
- per-context proxy attribution 불안정
- cleanup 후 target leak 지속
- outer sandbox가 Chromium sandbox를 깨뜨림
```

이 경우 v1은 `dedicated_process`를 기준 동작으로 시작할 수 있어야 한다.

---

## Phase 0 — Security substrate

구현:

- Rust workspace/domain skeleton
- immutable Chromium/CDP artifact
- sandbox supervisor abstraction
- user/PID/mount/net namespace
- private tmp/shm/profile quota
- cgroup v2
- worker ownership lease
- mandatory egress deny-all baseline
- Chromium debugging pipe
- TargetManager skeleton
- worker readiness behavior self-test

검증 게이트:

- Chromium start/stop 1,000회 후 orphan process/mount/netns 0
- worker SIGKILL + lease expiry 후 child Chromium 0
- worker SIGKILL 후 egress route 0
- host localhost/private network direct connect 실패
- 다른 shard private file/socket 접근 실패
- Chromium sandbox 실제 활성

Rollback:

- production admission을 열기 전 단계이므로 실패 시 shared mode 구현 진행 금지

---

## Phase 1 — Execution correctness

구현:

- CreateSessionOperation
- Session/Shard 독립 state axes
- Placement/worker epoch/version fencing
- SessionExecutor
- ActionLedger
- timeout/quiescence/reconciliation
- operation/action idempotency

검증 게이트:

- action transition 모든 fault point injection
- possible dispatch 이후 crash는 `OUTCOME_UNKNOWN`
- gateway retry가 duplicate click을 새 ActionId로 만들지 않음
- timeout action 종료 전 다음 mutating action 미실행
- close/action/control race property test

---

## Phase 2 — Single shard, multi-context

구현:

- BrowserShard actor
- BrowserContext create/dispose
- TargetManager full bootstrap
- page/frame/worker/service-worker registry
- per-context egress route
- primary page
- session TTL/idle timeout
- cleanup protocol
- shared/tenant-dedicated/dedicated placement

검증 게이트:

- 8 context 동시 생성/종료
- context storage isolation matrix 통과
- popup/OOPIF/worker before-run 설정 확인
- context cleanup 후 orphan target/download 0
- private IP/metadata/DNS rebinding 차단
- cross-session route 사용 실패

Rollback point:

```text
force_dedicated_process = true
max_contexts_per_shard = 1
```

이 rollback path는 이후 release에서도 항상 유지한다.

---

## Phase 3 — Typed Skill actions

구현:

- navigate/snapshot/node_ref
- strict selector + minimum actionability
- click/fill/type/scroll/select/dialog
- page management
- wait/read primitives
- privileged evaluate profile
- canonical action proposal/approval
- approval 조회/결정 API(polling 기반)
- action resolve/reconciliation API

검증 게이트:

- stale iframe/document/node ref 일관된 오류
- overlay/hit-test/disabled 기본 actionability
- approval TOCTOU 차단
- input dispatch 이후 자동 retry 없음
- privileged evaluate가 standard profile에서 불가
- RECONCILIATION_REQUIRED가 resolve/close 외 경로로 해제되지 않음

---

## Phase 4 — Artifact/PDF/Screenshot/Download

구현:

- Artifact state machine
- quota reservation/in-flight accounting
- object-store adapter/multipart cleanup
- screenshot preflight
- streaming PDF
- upload materialization
- download frame→session attribution
- quarantine/scanner hook
- janitor

검증 게이트:

- artifact cross-tenant 접근 0
- 대형 download/PDF/screenshot bounded abort
- object-store partial failure cleanup
- disk/inode full fail mode
- unmapped download cancel + shard health transition
- temp/multipart leak 0

---

## Phase 5 — Viewer/HITL

구현:

- shared screencast broadcaster
- immediate Chromium frame ack
- one-time viewer ticket
- input lease epoch/sequence
- frame transform epoch
- control acquire/release barrier
- disconnect input reset
- CJK composition protocol

검증 게이트:

- p95/p99 latency 목표
- slow viewer 4명이 Chromium stall을 일으키지 않음
- human control 중 agent mutating action 차단
- stale/replayed input reject
- disconnect during mouse-down/IME composition recovery
- Korean/Japanese/Chinese composition test

---

## Phase 6 — Scheduler/Limits

구현:

- regional tenant DRR
- worker reservation
- ResourceRequest vector
- host envelope
- SessionAdmission
- ActionAdmission
- workload observation/escalation
- drain/recycle

검증 게이트:

- multi-gateway duplicate reservation 없음
- mixed heavy/light tenant fairness
- PDF burst에서 shard/host OOM 방지
- hard memory/PID limit 동작
- target storm isolation/recovery

---

## Phase 7 — Business/Cluster

구현:

- gateway/worker split
- Redis directory/fencing
- PostgreSQL policy
- usage/audit WAL
- emergency kill switches
- event outbox + webhook/event polling 전달
- rolling drain
- SDK

검증 게이트:

- gateway restart 후 route 유지
- Redis partition degraded mode
- worker loss cleanup/session/action outcome 일관성
- rolling deployment은 spare capacity 조건에서 신규 create 유지
- audit sink failure/WAL full fail-closed policy
- webhook 연속 실패 시 bounded retry/suspend와 polling fallback 동작

---

## Phase 8 — Production canary

- dedicated-process canary 먼저
- tenant-dedicated shard
- shared-context 순으로 density를 단계적으로 올린다.

```text
contexts/shard = 1
 → 2
 → 4
 → 8
```

각 단계에서 security/isolation/cleanup/memory/error budget을 통과해야 다음 단계로 진행한다.

# 33. 운영 기본 정책

## 33.1 Standard plan

```text
isolation = shared_context
network_class = public
reuse_policy = cross_tenant
max contexts per shard = benchmark-confirmed, 초기 8 상한
raw CDP = disabled
evaluate = disabled
Chrome extension = disabled
arbitrary upstream proxy = disabled
Chromium sandbox = required
outer shard sandbox = required
network = public-web-default
```

보장 문구에는 session별 CPU/RAM hard isolation과 browser-process compromise isolation을 포함하지 않는다.

## 33.2 Enterprise secure plan

```text
isolation = tenant_dedicated_shard
reuse_policy = same_tenant_only
custom allowlist
approved extension optional
private artifact bucket optional
customer-managed encryption key optional
dedicated worker/network class optional
```

custom allowlist의 enforcement 단위는 §19.6의 CONNECT granularity 한계를 따르며, 이를 plan 보장 문구에 명시한다.

## 33.3 High isolation job

```text
isolation = dedicated_process
one session per Chromium
reuse_policy = no_reuse
strict TTL
evaluate/profile policy explicit
no process reuse after session close
```

## 33.4 Dedicated worker/private network

```text
isolation = dedicated_worker or dedicated pool
network_class = private/customer-specific
approved upstream proxy/certificate optional
hardware GPU/extension optional
separate DNS/route policy
```

이 tier는 public-web SSRF guarantee와 다른 threat model을 가질 수 있으므로 policy와 문서에 명시한다.

## 33.5 Runtime safety switches

운영자가 재배포 없이 설정 가능해야 한다.

```text
force_dedicated_process
max_contexts_per_shard
max_targets_per_session
disable_evaluate
disable_viewer_control
disable_downloads
disable_checkpoint
disable_chromium_artifact_digest
deny_domain/ip emergency rules
stop_new_sessions_by_network_class
```

Safety switch 변경은 audit event다.

# 34. Steel 대비 의도적 차이

| 영역 | Steel 중심 접근 | browserd v1 Draft 0.3 |
|---|---|---|
| 핵심 session 모델 | browser lifecycle 중심 | BrowserContext + SessionExecutor/TargetRegistry |
| process boundary | browser lifecycle | outer-sandboxed BrowserShard |
| multi-session | 기존 코어 확장 필요 | 기본 도메인 모델 |
| public CDP | 중요한 기능 | 제공하지 않음 |
| target lifecycle | 범용 browser API semantics | pause-before-run TargetManager |
| action retry | API 구현에 의존 | explicit ActionLedger / OUTCOME_UNKNOWN |
| scheduler | 제한적/별도 구현 필요 | operation queue + reservation + resource admission |
| tenant quota | 별도 구현 필요 | 코어 기능 |
| network | browser/proxy feature | mandatory netns egress security boundary |
| file scope | 재검토 필요 | tenant/session artifact state machine |
| viewer | 재사용 가치 높음 | lease epoch/IME를 가진 Feature Module |
| PDF/screenshot/scrape | 재사용 가치 높음 | ActionAdmission + artifact streaming |
| extension | 범용성 중시 | shared-context에서는 금지 |
| runtime | Node/Fastify | Rust/Tokio + sandbox supervisor |
| 목표 | 범용 browser API | AI Skill 전용 policy/runtime |

이 차이 때문에 Steel 전체 fork보다 greenfield가 장기적으로 더 단순하다는 결론은 유지한다. 다만 viewer/browser edge case behavior와 테스트는 적극 참고할 수 있다.

# 35. Release acceptance criteria

v1 production release는 다음을 모두 만족해야 한다.

## 기능

- CreateSession Operation create/get/cancel
- Session get/delete
- 여러 BrowserContext를 여러 outer-sandboxed shard에 배치
- TargetManager가 page/OOPIF/worker를 before-run bootstrap
- navigate/snapshot/click/fill/type/scroll/read actions
- screenshot/PDF
- upload/download artifact
- viewer read/control + CJK IME
- approval 조회/결정 API
- action resolve API
- event 전달(webhook/event polling) 또는 명시된 polling-only fallback
- tenant quota/DRR queue + worker reservation
- SessionAdmission/ActionAdmission
- session TTL/idle timeout
- shard drain/recycle

## 보안

- raw CDP 미노출
- Chromium sandbox 활성
- production shard outer sandbox 활성
- direct Chromium outbound 불가
- loopback/private/metadata SSRF 차단
- inspected IP와 actual connect target 일치
- tenant/session capability/fencing 검증
- artifact namespace isolation
- shared-context extension/arbitrary proxy 금지
- secret/log redaction
- approval proposal TOCTOU/replay 방어
- worker loss 시 egress route revoke

## 정확성/안정성

- unmanaged target 0
- context cleanup 후 orphan target/download 0
- duplicate idempotency 정상 retry 중복 dispatch 0
- possible-dispatch 장애에서 자동 replay 0
- `OUTCOME_UNKNOWN` fault tests 통과
- timeout 후 mutating action ordering 보존
- shard crash가 다른 shard Chromium에 전파되지 않음
- worker death 후 owned Chromium cleanup
- Redis/object-store/audit 일시 장애 시 정의된 degraded mode 준수
- disk/inode/PID/OOM resource failure 정의 준수

## 관측성

- operation/session/action/target/shard metric
- distributed trace
- action uncertainty metric
- immutable audit delivery 또는 bounded WAL
- usage event
- tenant/session 기준 structured diagnostic 가능
- 고카디널리티 tenant/session metric label 없음

## 성능

- warm/cold create 목표 또는 승인된 대체 기준
- viewer p95/p99 latency 목표
- ActionAdmission을 포함한 burst workload SLA
- contexts-per-shard 기본값을 benchmark로 확정
- 최소 72시간 mixed-workload soak에서 leak slope 허용 범위

## Shared-context release blocker

다음 중 하나라도 재현되면 shared-context production release를 차단한다.

```text
cross-context storage/permission/download attribution 혼선
Chromium direct outbound 성공
localhost/link-local mandatory proxy 우회
bootstrap 전에 target code/network 실행
다른 shard private filesystem/service 접근 성공
timeout action의 late effect와 다음 mutating action 순서 역전
OUTCOME_UNKNOWN action 자동 replay
worker loss 후 Chromium/egress route 잔존
unmapped download가 다른 session에 귀속
```

이 경우 `force_dedicated_process`로 출시하는 것은 별도 acceptance를 통과하면 허용할 수 있다.

## Runtime rollback trigger

production에서 다음이 baseline을 넘으면 신규 shared placement를 중지한다.

- orphan/unmapped target 증가
- cleanup failure 증가
- Chromium artifact 변경 후 isolation regression
- browser crash/taint rate 급증
- memory leak slope regression
- unexplained action outcome_unknown 급증

운영 순서:

```text
1. shared admission stop
2. force_dedicated_process 또는 max_contexts=1
3. suspect Chromium artifact canary disable
4. 기존 shard drain
5. 원인 확인 후 단계적 density 재개
```

# 36. 최종 권고안

v1은 다음 구성으로 시작한다.

```text
Rust browserd
├─ Gateway
│  ├─ Auth / Capability
│  ├─ Operation / Idempotency
│  ├─ Regional DRR
│  └─ Fenced Session Router
│
├─ Worker
│  ├─ Reservations
│  ├─ SessionExecutor
│  ├─ ActionLedger
│  ├─ TargetManager
│  ├─ Session/Action Admission
│  └─ Artifact/Viewer clients
│
├─ BrowserShard
│  ├─ outer user/pid/mount/net sandbox
│  ├─ cgroup + private tmp/shm/profile
│  ├─ Chromium sandbox ON
│  ├─ Session = BrowserContext
│  ├─ pause-before-run target bootstrap
│  └─ mandatory per-session egress route
│
├─ Egress Policy Proxy
│  ├─ DNS/IP/connect-target validation
│  ├─ network quota
│  └─ no arbitrary shared-tier upstream proxy
│
├─ session-scoped Artifact state machine
├─ Viewer/HITL with fencing + CJK IME
└─ compile-time Feature Modules with limited internal capabilities
```

초기 density는 안전하게 단계적으로 올린다.

```text
dedicated process / contexts-per-shard=1
       ↓ validation
2 contexts/shard
       ↓
4 contexts/shard
       ↓
8 contexts/shard
```

`8`은 목표 기본값이지 architecture invariant가 아니다.

핵심적인 제품 경계는 다음과 같이 정의한다.

> **browserd는 Chromium을 원격으로 빌려주는 CDP 프록시가 아니다. BrowserContext를 효율적인 application-level session 경계로 사용하되 Chromium process 전체는 별도의 shard sandbox에 가두고, 모든 target·action·network·artifact를 server-side capability와 state machine으로 통제하는 멀티테넌트 브라우저 런타임이다.**

보안 경계는 다음처럼 명확히 설명한다.

> **shared_context는 동일 Chromium browser process 내부의 browser compromise 위험을 공유한다. 대신 outer ShardSandbox는 그 위험이 다른 shard, worker service, host network로 쉽게 확산되지 않도록 containment한다. 더 강한 tenant/job 격리가 필요하면 tenant-dedicated, dedicated-process, dedicated-worker profile을 사용한다.**

이 경계를 유지하면 per-session VM 비용을 강제하지 않으면서도 Cloudflare Browser Rendering과 유사한 운영형 browser fleet에 필요한 quota, fairness, HITL, artifact, SSRF, failure containment, rollout control을 제품 핵심으로 구현할 수 있다.
