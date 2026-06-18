#### The HTTP connector has been substantially expanded in version 2.0.0:

##### What's Added

- **Authentication Type configuration picklist** with conditional credential fields:
    - `None` (existing behavior)
    - `Basic` (username + password)
    - `Bearer Token`
    - `API Key Header` (configurable header name + masked value)
    - `API Key Query Param` (configurable param name + masked value)
    - `OAuth2 Client Credentials` (token URL + client ID + client secret + scope; access tokens are cached in-process keyed by `(token_url, client_id, scope)` and refreshed 30 seconds before expiry)
- **Per-action authentication override** on every action: if `Per-Call Auth Override` is set, that single call uses the supplied auth instead of the connection-level one. All matching credential fields are exposed.
- **Connection-level Default Custom Headers** — a JSON field whose contents are merged into every outgoing request. Per-action `Headers` win on collision.
- **Per-action knobs** added across all verb actions:
    - `Body Type` selector: `none` / `json` / `form` / `raw` / `multipart`.
    - `Timeout` override.
    - `Follow Redirects` toggle.
    - `Response Path` — pluck a sub-field from the response body via dot/bracket notation (e.g. `data.results[0].id`).
    - `Raw Response (binary-safe)` — return content as base64 instead of parsing.
- **Smart response parsing** — the connector now auto-detects the `Content-Type` and returns JSON as a parsed object, text/XML/HTML as a string, and binary content wrapped in a base64 envelope. Every response includes `status_code`, `headers`, and `body`.
- **Retry / backoff** — connection-level `Max Retries`, `Retry Backoff Factor`, and `Retry On Status` (defaults to `429,500,502,503,504`). Implemented with `urllib3`'s `Retry` and respects the `Retry-After` header.
- **Return On HTTP Error** toggle — when true (default), non-2xx responses are returned to the playbook so it can branch on `status_code`; when false, they raise.
- **New operation: HTTP Request (Any Method)** — a single freeform action with a method picklist, replacing the need to choose between seven verb-specific actions for ad-hoc calls.
- **New operation: HTTP Paginate** — walks paginated endpoints and concatenates results. Three modes:
    - `link_header` — RFC 5988 `next` rel link.
    - `next_url_path` — next URL plucked from a JSON path inside the response body.
    - `page_param` — bumps a numeric query parameter until the items list comes back empty.
    Returns `{items, pages_fetched, truncated}` with a configurable `Max Pages` cap and infinite-loop protection via a seen-URL set.
- **New operation: Fetch Records (Ingestion)** — calls a configured endpoint, optionally paginates, plucks records via a response path, and returns a flat list. Used by scheduled data ingestion.
- **Data ingestion support** — `ingestion_supported: true` with `scheduled` mode and an `ingestion_config_schema` covering fetch URL, method, response path, pagination mode, and pagination parameters. The `ingest_mapping_template` is intentionally minimal so playbooks can map fields per deployment.

##### What's Improved

- The Server URL is now optional, allowing the connector to be used purely with absolute URLs supplied per action.
- Health check now treats `401` / `403` / `404` responses as healthy (the server is reachable, even if the root URL requires auth).

#### Breaking changes

- The previous connection-level configuration only had `Server URL`, `Port`, and `Verify SSL`. Existing configurations continue to work unchanged: `Authentication Type` defaults to `None`, all new fields default to safe values, and the seven existing verb actions retain their original parameters with the new optional knobs added on top.
