# browserd Python client

Standard-library-only client for every public browserd `/v1` HTTP route. It generates request and
idempotency IDs, decodes typed error envelopes, polls operations/actions, and resumes event polling.

```python
from browserd import BrowserdClient

client = BrowserdClient("https://browserd.example", token="service-capability")
created = client.create_session({"isolation": "shared_context"})
```

Mutating transport uncertainty raises `DispatchUncertainError` without replay. An
`outcome_unknown` action remains a normal terminal response and is never automatically retried.
Expired event cursors raise `EventGapError` so callers can poll authoritative resource state.
Base URLs must be HTTP(S) and cannot contain credentials, query parameters, or fragments.

Run tests with `PYTHONPATH=. python3 -m unittest discover -s tests -v`.
