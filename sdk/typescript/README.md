# browserd TypeScript client

Dependency-free client for the public browserd `/v1` API. It uses the platform `fetch`, generates
`X-Request-Id` and idempotency keys, provides operation/action polling and resumable event polling,
and exposes every public HTTP route in `SPEC.md`.

```ts
import { BrowserdClient } from "@browserd/client";

const client = new BrowserdClient({ baseUrl: "https://browserd.example", token: process.env.BROWSERD_TOKEN });
const created = await client.createSession({ isolation: "shared_context" });
```

Safety behavior is deliberately conservative:

- a transport failure during a mutating request raises `DispatchUncertainError` and is never replayed;
- `status: "outcome_unknown"` is returned as a terminal `ActionResponse`, never thrown or retried;
- only reads/idempotent deletes and explicitly known pre-dispatch error codes are retried;
- event retention gaps raise `EventGapError`; callers must poll authoritative resource state.
- base URLs must be HTTP(S) and cannot contain credentials, query parameters, or fragments.

Run tests with `npm test` on Node.js 22.18 or newer.
