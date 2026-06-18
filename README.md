# HTTP Connector

Generic HTTP client for FortiSOAR. One connector, any REST API: arbitrary methods, configurable auth, retry, pagination, file upload, and scheduled ingestion.

There are a lot of fields. Most you can ignore. This README is a map: pick your scenario, see which fields matter, ignore the rest.

---

## TL;DR — which fields do I actually need?

| You want to…                                                    | Set these                                                                                          | Leave the rest alone |
|-----------------------------------------------------------------|----------------------------------------------------------------------------------------------------|----------------------|
| Call a public unauthenticated API                               | `server_url`, action's `rest_api`                                                                  | everything else      |
| Call an API with a static token                                 | `server_url`, `auth_type=Bearer Token`, `bearer_token`                                             | —                    |
| Call an API behind login (FortiSOAR-style `/auth/authenticate`) | `auth_type=Token Login` + the Login fields                                                         | —                    |
| Call an OAuth2 client-credentials API                           | `auth_type=OAuth2 Client Credentials` + token URL / client id / secret                             | —                    |
| Hit two APIs needing different auth                             | Create a separate connector configuration per API and pick the right one in each action            | —                    |
| Walk paginated endpoints                                        | Use **HTTP Paginate** action (not GET in a loop)                                                   | —                    |
| Upload an FSR attachment somewhere                              | Use **Upload File** action with `attachment_id`                                                    | —                    |
| Download a remote file into FSR                                 | Use **Download File** action with `rest_api`                                                       | —                    |

---

## How vendor auth translates to connector fields

Vendor docs show Python (or curl) examples. Here's how to read them and map to the connector.

---

**Static API key in a header**

```python
# What the vendor shows you
requests.get(url, headers={"X-API-Key": "abc123"})
```

```
auth_type:           API Key Header
api_key_header_name: X-API-Key
api_key:             abc123
```

Why a dedicated auth type and not Default Custom Headers? Because `api_key` is stored encrypted. Default Custom Headers is plaintext — don't put secrets there.

---

**Static API key as a query parameter**

```python
# What the vendor shows you
requests.get(url, params={"api_key": "abc123"})
```

```
auth_type:          API Key Query Param
api_key_param_name: api_key
api_key:            abc123
```

---

**Bearer token (static, long-lived)**

```python
# What the vendor shows you
requests.get(url, headers={"Authorization": "Bearer eyJhbG…"})
```

```
auth_type:     Bearer Token
bearer_token:  eyJhbG…
```

No login step needed — paste the token directly.

---

**OAuth2 client credentials (machine-to-machine)**

```python
# What the vendor shows you
import requests
resp = requests.post(
    "https://idp.example.com/oauth/token",
    data={"grant_type": "client_credentials",
          "client_id": "my-app",
          "client_secret": "secret"},
)
token = resp.json()["access_token"]
requests.get(url, headers={"Authorization": f"Bearer {token}"})
```

```
auth_type:          OAuth2 Client Credentials
oauth_token_url:    https://idp.example.com/oauth/token
oauth_client_id:    my-app
oauth_client_secret: secret
oauth_scope:        (blank, or e.g. "read:all" if required)
```

The connector handles the token fetch and caches it until expiry — you don't write the two-step flow.

---

**Username/password login → JWT on subsequent calls**

```python
# What the vendor shows you
resp = requests.post("/api/auth/login",
                     json={"username": "admin", "password": "secret"})
token = resp.json()["access_token"]
requests.get("/api/things", headers={"Authorization": f"Bearer {token}"})
```

```
auth_type:            Token Login
login_url:            /api/auth/login
login_body_type:      json
login_username:       admin
login_password:       secret
login_username_field: username        ← matches the json key
login_password_field: password        ← matches the json key
login_token_path:     access_token   ← dot path into login response
login_header_name:    Authorization
login_header_prefix:  Bearer
```

If the vendor example uses `{"email": "…", "passwd": "…"}` instead, change `login_username_field=email` and `login_password_field=passwd`. The connector builds the body dict from those field name settings.

---

**API key sent on login request as a header → short-lived JWT returned**

```python
# What the vendor shows you (e.g. Yeti)
resp = requests.post(
    "https://yeti/api/v2/auth/api-token",
    headers={"x-yeti-apikey": "eyJhbG…long-lived-key…"},
)
token = resp.json()["access_token"]
requests.get("/api/v2/observables/", headers={"Authorization": f"Bearer {token}"})
```

```
auth_type:              Token Login
login_url:              https://yeti/api/v2/auth/api-token
login_body_type:        header_only
login_request_headers:  {"x-yeti-apikey": "eyJhbG…long-lived-key…"}
login_token_path:       access_token
login_header_name:      Authorization
login_header_prefix:    Bearer
```

`header_only` means no body is sent on the login POST — only the headers. The long-lived API key is a connection-level secret stored in `login_request_headers` (encrypted password field).

---

**Plain string token in login response body (filebrowser)**

```python
# What the vendor shows you
resp = requests.post("/api/login",
                     json={"username": "admin", "password": "secret"})
token = resp.text   # NOT resp.json() — body is a bare string
requests.get("/api/resources/", headers={"X-Auth": token})
```

```
auth_type:            Token Login
login_url:            /api/login
login_body_type:      json
login_username:       admin
login_password:       secret
login_token_path:                    ← BLANK — body IS the token, no path to walk
login_header_name:    X-Auth
login_header_prefix:                 ← blank — no "Bearer " prefix
```

---

## Configuration (connection-level)

These apply to **every** call this connection makes.

### Connection target

| Field          | When to set                                                                                      | Notes                                                              |
|----------------|--------------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| **Server URL** | Set this if most calls hit the same host. Actions can then use relative paths like `/v1/things`. | Leave blank only if every action will pass a full `https://…` URL. |
| **Port**       | Only if the URL doesn't already include one.                                                     | Usually leave blank — most URLs encode the port.                   |

### Authentication Type

Pick one. The form reveals the matching credential fields after you select.

| Auth Type                     | Use for                                                                                                                                                                                                      | Required fields                                                                     |
|-------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| **None**                      | Public APIs.                                                                                                                                                                                                 | —                                                                                   |
| **Basic**                     | HTTP Basic (legacy admin APIs, internal tools).                                                                                                                                                              | `basic_username`, `basic_password`                                                  |
| **Bearer Token**              | Static long-lived tokens (most modern REST APIs, PATs, GitHub-style).                                                                                                                                        | `bearer_token` — sent as `Authorization: Bearer <token>`.                           |
| **API Key Header**            | APIs that want a key on a custom header (`X-API-Key`, `apikey`, etc.).                                                                                                                                       | `api_key_header_name`, `api_key`                                                    |
| **API Key Query Param**       | Legacy / lightweight APIs that take the key on the URL (`?api_key=…`).                                                                                                                                       | `api_key_param_name`, `api_key`                                                     |
| **OAuth2 Client Credentials** | Machine-to-machine OAuth. Token is fetched once, cached, refreshed on expiry.                                                                                                                                | `oauth_token_url`, `oauth_client_id`, `oauth_client_secret`, optional `oauth_scope` |
| **Token Login**               | "Log in with username/password, get a token, send it on subsequent calls" — e.g. FortiSOAR `/auth/authenticate`, filebrowser, many appliance APIs. The connector handles the login + token plumbing for you. | See Token Login fields below.                                                       |

#### Token Login fields

Token Login is for APIs that require a login call to exchange credentials for a session token, which is then sent on every subsequent request. There are three distinct vendor patterns — pick the one that matches your API.

| Field                  | Default                 | Meaning                                                                                                                                                                    |
|------------------------|-------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `login_url`            | —                       | Where to POST. Relative paths join Server URL.                                                                                                                             |
| `login_body_type`      | `json`                  | `json` = credentials in request body. `header_only` = no body, credentials go in `login_request_headers` only (see pattern 3 below).                                       |
| `login_request_headers`| (blank)                 | JSON object of headers sent **on the login request**. Required for `header_only`. Also accepted for `json` mode (merged with the body). Store as a password field.          |
| `login_username` / `login_password` | —          | The credentials. Only required for `json` body type.                                                                                                                        |
| `login_username_field` / `login_password_field` | `username` / `password` | JSON body keys. Change if the API expects `email` / `passwd` / `user`, etc. |
| `login_token_path`     | (blank)                 | Dot path to the token inside the JSON response (e.g. `access_token`, `data.token`). **Leave blank if the response body is the bare token string** (filebrowser does this). |
| `login_header_name`    | `X-Auth`                | Header to send the token on for subsequent calls. Use `Authorization` for Bearer-style.                                                                                    |
| `login_header_prefix`  | (blank)                 | Prefix prepended to the token. Use `Bearer ` (trailing space) for `Authorization: Bearer <token>`.                                                                         |

#### Token Login — three vendor patterns

**Pattern 1 — POST username/password body → get JWT (most common)**

Used by: FortiSOAR `/api/auth/authenticate`, Grafana, many appliance APIs.

```
login_url:            /api/auth/login
login_body_type:      json
login_username:       admin
login_password:       ••••••••
login_username_field: username          ← or "email", "user", whatever the API expects
login_password_field: password          ← or "passwd", "pass", etc.
login_token_path:     access_token      ← dot path to token in JSON response
login_header_name:    Authorization
login_header_prefix:  Bearer            ← trailing space is intentional
```

Why `login_username_field` exists: vendors can't agree on the body key name. `{"username":"…"}`, `{"email":"…"}`, `{"user":"…"}` are all common — this lets you match what the API documents without touching code.

---

**Pattern 2 — POST body → bare token string in response (filebrowser-style)**

Used by: filebrowser, some legacy APIs that return a raw token string (no JSON wrapper).

```
login_url:            /api/login
login_body_type:      json
login_username:       admin
login_password:       ••••••••
login_token_path:                       ← LEAVE BLANK — response body IS the token
login_header_name:    X-Auth            ← filebrowser's expected header
login_header_prefix:                    ← blank — no prefix
```

Why `login_token_path` is blank: normally you'd dot-walk into `{"access_token": "…"}` to pluck the value. When the entire response body is the token string (`eyJhbG…`), there's nothing to walk into — blank means "use the body as-is".

---

**Pattern 3 — POST with API key in header → get JWT (Yeti, some threat-intel APIs)**

Used by: Yeti (`x-yeti-apikey`), APIs that treat an existing long-lived key as login credentials sent via header rather than body.

```
login_url:              /api/v2/auth/api-token
login_body_type:        header_only
login_request_headers:  {"x-yeti-apikey": "eyJhbG…"}   ← the static API key
login_token_path:       access_token
login_header_name:      Authorization
login_header_prefix:    Bearer
```

Why `header_only` exists: these APIs don't accept a username/password body at all — the login endpoint authenticates the caller via a request header. `header_only` sends no body; `login_request_headers` carries the secret. The connector then extracts the short-lived token from the response and forwards it on every subsequent call.

> **When to just use Bearer Token instead:** if the API gives you a long-lived static token and there is no login endpoint, skip Token Login entirely — `auth_type=Bearer Token` and paste the token. Token Login is only worth configuring when the API forces an exchange step.

> **Multiple APIs with different auth in one playbook?** Create a separate connector configuration per API. Auth is connection-level by design — there is no per-call auth override.

### Headers, timeout, retry

| Field                      | Default               | When to change                                                                                                                                                                  |
|----------------------------|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Default Custom Headers** | `{}`                  | Constant non-secret headers for every call (`User-Agent`, `Accept`, custom tracing). **Never put secrets here** — they're stored in plaintext. Use API Key Header auth instead. |
| **Request Timeout**        | `60` s                | Bump for slow endpoints; per-action override available.                                                                                                                         |
| **Max Retries**            | `0` (off)             | Set to `3` for flaky APIs. Combined with the next two.                                                                                                                          |
| **Retry Backoff Factor**   | `0.5`                 | Sleep between retries = `factor * 2^(retry-1)` (urllib3). Leave alone unless you understand urllib3.                                                                            |
| **Retry On Status**        | `429,500,502,503,504` | Codes that trigger retry.                                                                                                                                                       |
| **Return On HTTP Error**   | `true`                | When true (recommended), 4xx/5xx come back as a normal result (status_code + body) so playbooks can branch on them. Set false if you want exceptions to halt the playbook.      |
| **Verify SSL**             | `true`                | Disable only for dev / self-signed boxes.                                                                                                                                       |

---

## Actions

Most users only need three: **HTTP GET**, **HTTP POST**, **HTTP Request (Any Method)**. The rest are conveniences or specialized.

### Common request parameters (most actions share these)

| Param              | What it does                                                                                             |
|--------------------|----------------------------------------------------------------------------------------------------------|
| `rest_api`         | URL or path. Relative = joined to Server URL. Absolute = used as-is, which is how you override per call. |
| `parameter`        | Query params. `{"k":"v"}` or `[{"key":"k","value":"v"}]`.                                                |
| `header`           | Per-call headers. Merged on top of Default Custom Headers.                                               |
| `body_type`        | `none` / `json` / `form` / `raw` / `multipart`. See below.                                               |
| `data`             | The body. Shape depends on body_type.                                                                    |
| `timeout`          | Per-call timeout override.                                                                               |
| `follow_redirects` | Default true. Turn off if you need to inspect a 3xx.                                                     |
| `response_path`    | Dot/bracket path to pluck from the response (e.g. `data.results`). Saves a downstream JMESPath.          |
| `raw_response`     | Return content base64-encoded. Use for binary downloads.                                                 |

#### Body Type — pick one

| body_type   | When                                                                        | What `data` should look like                                              |
|-------------|-----------------------------------------------------------------------------|---------------------------------------------------------------------------|
| `none`      | GET / DELETE / no body                                                      | (omit)                                                                    |
| `json`      | Most modern APIs                                                            | `{"name":"x", "items":[1,2]}` — sent as `Content-Type: application/json`. |
| `form`      | Old endpoints expecting `application/x-www-form-urlencoded`                 | `{"key":"value"}`                                                         |
| `multipart` | Form with files (use **Upload File** action instead for actual file upload) | `{"field":"value"}`                                                       |
| `raw`       | XML / plain text / SOAP / anything else                                     | A string. Set the right `Content-Type` header yourself.                   |

### Action picker

| Action                                                      | Use when                                                                                                                 |
|-------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| **HTTP GET / POST / PUT / PATCH / DELETE / HEAD / OPTIONS** | You know the method. Slightly leaner forms.                                                                              |
| **HTTP Request (Any Method)**                               | Method is dynamic (Jinja-driven).                                                                                        |
| **HTTP Paginate**                                           | The endpoint paginates and you want everything in one result. See pagination section.                                    |
| **Fetch Records (Ingestion)**                               | Same as Paginate, but the result is shaped for the FSR ingestion framework. This is also what scheduled ingestion calls. |
| **Upload File**                                             | Push an FSR attachment (or file IRI) to a third-party endpoint. See below.                                               |

> **Multiple APIs / multiple auths?** Create a separate connector configuration for each. There is no per-call auth override — keep auth as a connection concern, not an action concern.

---

## Pagination

Three modes, all also available in scheduled ingestion config:

| Mode            | The API does this                                           | Required fields                                                 |
|-----------------|-------------------------------------------------------------|-----------------------------------------------------------------|
| `link_header`   | RFC 5988 — sends `Link: <…>; rel="next"`                    | (nothing extra)                                                 |
| `next_url_path` | Embeds a full next URL inside the JSON body                 | `next_url_path` = dot path, e.g. `links.next` or `meta.nextUrl` |
| `page_param`    | You bump a numeric query parameter (`?page=2`, `?page=3` …) | `page_param_name` (default `page`), `start_page`, `max_pages`   |

`items_path` (Paginate) / `response_path` (Fetch Records) tells the connector where the **records list** lives inside each page so it can concatenate them. Leave blank if the body itself is already a list.

`max_pages` is your circuit breaker (default 50). If the result says `truncated: true`, raise it.

---

## Upload File action

Stream-uploads a file to any HTTP endpoint. **Does not buffer through the playbook engine** — bytes flow from FSR's file store directly to the destination.

| Param           | Notes                                                                                                                                                                             |
|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `attachment_id` | Pass an FSR Attachment `@id` (`/api/3/attachments/<uuid>`), a File IRI, or the whole attachment record. The connector dereferences Attachment → File automatically (since 2.0.2). |
| `file_iri`      | Alternative if you already have a `/api/3/files/<uuid>` IRI.                                                                                                                      |
| `file_path`     | Advanced: absolute path on the integration agent. Bypasses FSR lookup. Used by automated tests, mostly.                                                                           |
| `filename`      | Override the destination filename. Default = the FSR file's name.                                                                                                                 |
| `upload_mode`   | `multipart` (standard form upload) or `raw_body` (file bytes are the request body — S3 PUT, filebrowser, presigned URLs).                                                         |
| `field_name`    | Multipart only. The form field the file goes on. Default `file`. Some APIs want `attachment`, `data`, etc.                                                                        |
| `extra_fields`  | Multipart only. Extra non-file form fields, e.g. `{"folder":"reports"}`.                                                                                                          |
| `content_type`  | Default `application/octet-stream`. Set to e.g. `text/csv` for friendlier server-side handling.                                                                                   |
| `rest_api`      | Destination. `{filename}` placeholder is substituted with the (URL-encoded) source filename.                                                                                      |

> **Don't pass a file's bytes through `data:` on `http_post` to upload.** Use this action — it sidesteps playbook-engine size limits and handles streaming.

---

## Download File action

The reverse of Upload File. GETs a remote URL and either creates an FSR Attachment or drops the file on the integration agent. Streams to disk — the response body never goes through the playbook engine.

| Param | Notes |
|---|---|
| `rest_api` | URL to download. Relative paths join Server URL. |
| `method` | `GET` (default) or `POST`. Use POST only if the server demands a request body to produce the file. |
| `create_attachment` | `true` (default) → file becomes an FSR Attachment record. `false` → file stays on the integration agent, path returned in `downloaded.file_path`. |
| `attachment_name` | Display name for the Attachment record. Defaults to the resolved filename. |
| `description` | Optional Attachment description. |
| `filename` | Force a specific filename. Otherwise resolved from `Content-Disposition` → URL basename → `download.bin`. |
| `parameter` / `header` | Query params and per-call headers, same as other actions. |
| `body_type` / `data` | Only for POST downloads. |
| `timeout` | Default 300 s — bigger than normal because downloads can be slow. |

**Output:**

```
status_code: 200
headers: {…response headers…}
downloaded:
  filename: "report.csv"
  bytes: 5795363
  attachment: { @id: "/api/3/attachments/<uuid>", file: {…}, … }   # when create_attachment=true
  file_path: "/tmp/report.csv"                                      # when create_attachment=false
```

> Use `create_attachment=false` only when a downstream step on the same agent will consume the file by path — otherwise the file is orphaned on disk.

---

## Scheduled Data Ingestion

If the connector is configured for ingestion, FortiSOAR will call **Fetch Records** on a schedule. The ingestion config exposes the same `fetch_url` / `method` / `response_path` / pagination fields as the action — same semantics, same defaults. The
`ingest_mapping_template` shapes the resulting records into FSR alerts/feeds via the standard ingestion pipeline.

---

## Reading the output

Every action returns the same envelope:

```
data:
  status_code: 200
  headers: { Content-Type: "application/json", … }
  body: { … parsed response … }
```

FSR always wraps connector output in `data`, so real content is always at `data.body.*`. This is intentional — `status_code` and `headers` are often needed for branching and debugging, and separating them from the body avoids field-name collisions.

**Referencing fields in a downstream step:**

```
{{ vars.steps.MyStep.data.body.observables }}       ← list of observables
{{ vars.steps.MyStep.data.body.results[0].ip }}     ← first result's IP field
{{ vars.steps.MyStep.data.status_code }}            ← branch on HTTP status
```

**Reducing the path with `response_path`:** set it on the action step and `data.body` becomes the hoisted value rather than the full response body. If `response_path=observables`, then `data.body` is the observables list directly — `data.body[0]` is the first record.

Use `response_path` when your playbook only cares about one sub-key and you want cleaner Jinja in downstream steps. Leave it blank when you need `status_code` or multiple keys from the body.

---

## Common gotchas

- **`Resolved file not found on disk for IRI …`** — you handed the file resolver an Attachment IRI on an older build. 2.0.2+ dereferences Attachment → File automatically; bump the connector.
- **`Could not resolve attachment reference`** — you passed `null` or a malformed object. Pass the `@id` string or the full attachment record.
- **OAuth keeps re-authenticating** — token cache is per-connection-config-hash. Changing any OAuth field (incl. scope) invalidates it. Expected.
- **`Verify SSL`-related TLS errors against an FSR appliance** — disable Verify SSL or install the appliance CA on the integration agent. Don't disable verify in production for public APIs.
- **Headers in Default Custom Headers leaked in support bundles** — yes, they're plaintext. Don't put secrets there; use API Key Header auth.
- **Token Login against filebrowser returns `body is not JSON`** — set `login_token_path` blank; filebrowser returns the raw token string, not JSON.
- **Token Login: `login_request_headers` must be a valid JSON object string** — e.g. `{"x-yeti-apikey":"eyJ…"}`. A bare string or Python dict won't parse.
- **Token Login `header_only` with no `login_request_headers` set** — raises `ConnectorError: login_request_headers required`. Set the field even if you leave username/password blank.
- **Token Login re-authenticates on every call** — by design; there is no token cache. If the API rate-limits login calls, use Bearer Token with a long-lived token instead.
- **Pagination returns nothing** — `items_path` / `response_path` is wrong. Run a single GET first, look at the response, find the array.
