"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

import json as _json
import os
import re
import time
from base64 import b64encode
from urllib.parse import urlencode, urlparse, urljoin, parse_qsl, quote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from connectors.core.connector import ConnectorError, get_logger

logger = get_logger('http')

SSL_VALIDATION_ERROR = 'SSL certificate validation failed'
CONNECTION_TIMEOUT = 'The request timed out while trying to connect to the remote server'
REQUEST_READ_TIMEOUT = 'The server did not send any data in the allotted amount of time'

AUTH_NONE = 'None'
AUTH_BASIC = 'Basic'
AUTH_BEARER = 'Bearer Token'
AUTH_API_KEY_HEADER = 'API Key Header' #pragma: allowlist secret
AUTH_API_KEY_QUERY = 'API Key Query Param' #pragma: allowlist secret
AUTH_OAUTH2_CC = 'OAuth2 Client Credentials'
AUTH_TOKEN_LOGIN = 'Token Login'

# Module-level OAuth2 token cache keyed by (token_url, client_id, scope).
_OAUTH_TOKEN_CACHE = {}


# ---------------------------------------------------------------------------
# Config / URL helpers
# ---------------------------------------------------------------------------

def _to_dict(value):
    """Coerce a parameter into a dict. Accepts dict, JSON string, or '' / None."""
    if value in (None, '', 0, '0'):
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = _json.loads(value)
        except ValueError:
            raise ConnectorError("Expected JSON object, got: {0!r}".format(value[:120]))
        if not isinstance(parsed, dict):
            raise ConnectorError("Expected JSON object, got {0}".format(type(parsed).__name__))
        return parsed
    raise ConnectorError("Expected dict or JSON object string, got {0}".format(type(value).__name__))


def _to_list_of_pairs(value):
    """Accept a dict OR a list of {'key':..,'value':..} entries → list of (k, v) tuples."""
    if value in (None, '', 0):
        return []
    if isinstance(value, dict):
        return list(value.items())
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, dict) and 'key' in item:
                out.append((item['key'], item.get('value', '')))
        return out
    raise ConnectorError("Expected dict or list of key/value entries.")


def _build_base_url(config):
    server_url = (config.get('server_url') or '').strip()
    port = config.get('port')
    verify_ssl = bool(config.get('verify_ssl', True))
    if not server_url:
        return ''
    if not server_url.startswith('http://') and not server_url.startswith('https://'):
        server_url = ('https://' if verify_ssl else 'http://') + server_url
    if port:
        # Insert port if not already present in the netloc.
        parsed = urlparse(server_url)
        if ':' not in parsed.netloc:
            server_url = '{0}://{1}:{2}{3}'.format(parsed.scheme, parsed.netloc, port, parsed.path or '')
    return server_url.rstrip('/')


def _resolve_url(config, rest_api):
    """If rest_api is absolute, use it as-is; else join with the configured base URL."""
    rest_api = (rest_api or '').strip()
    if rest_api.startswith('http://') or rest_api.startswith('https://'):
        return rest_api
    base = _build_base_url(config)
    if not base:
        raise ConnectorError("No Server URL configured and the request path is not absolute.")
    if not rest_api.startswith('/'):
        rest_api = '/' + rest_api
    return base + rest_api


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _oauth2_client_credentials_token(config):
    token_url = (config.get('oauth_token_url') or '').strip()
    client_id = (config.get('oauth_client_id') or '').strip()
    client_secret = config.get('oauth_client_secret') or ''
    scope = (config.get('oauth_scope') or '').strip()
    if not token_url or not client_id:
        raise ConnectorError("OAuth2 Client Credentials requires Token URL and Client ID.")
    cache_key = (token_url, client_id, scope)
    cached = _OAUTH_TOKEN_CACHE.get(cache_key)
    if cached and cached['expires_at'] > time.time() + 30:
        return cached['access_token']
    data = {'grant_type': 'client_credentials', 'client_id': client_id, 'client_secret': client_secret}
    if scope:
        data['scope'] = scope
    verify_ssl = bool(config.get('verify_ssl', True))
    resp = requests.post(token_url, data=data, verify=verify_ssl, timeout=int(config.get('timeout') or 60))
    if not resp.ok:
        raise ConnectorError("OAuth2 token request failed ({0}): {1}".format(resp.status_code, resp.text[:300]))
    body = resp.json()
    token = body.get('access_token')
    if not token:
        raise ConnectorError("OAuth2 token response missing 'access_token': {0}".format(body))
    expires_in = int(body.get('expires_in') or 3600)
    _OAUTH_TOKEN_CACHE[cache_key] = {'access_token': token, 'expires_at': time.time() + expires_in}
    return token


def _token_login(config):
    """POST to the configured login URL, return the token string.
    Runs every request — no caching, by design.

    Two modes controlled by ``login_body_type``:
      - ``json`` (default): sends {login_username_field: user, login_password_field: pw}
        as a JSON body. Requires login_username.
      - ``header_only``: sends no body — credentials go in request headers only via
        ``login_request_headers`` (a JSON object, e.g. {"x-yeti-apikey": "<key>"}).
        Used for APIs like Yeti where the secret is a header, not a body param.
    """
    login_url = (config.get('login_url') or '').strip()
    if not login_url:
        raise ConnectorError("Token Login requires Login URL.")
    body_type = (config.get('login_body_type') or 'json').strip().lower()
    token_path = (config.get('login_token_path') or '').strip() or None
    url = _resolve_url(config, login_url)
    verify_ssl = bool(config.get('verify_ssl', True))
    timeout = int(config.get('timeout') or 60)
    # Extra headers to send on the login request (e.g. x-yeti-apikey).
    login_headers = _to_dict(config.get('login_request_headers') or {})
    if body_type == 'header_only':
        if not login_headers:
            raise ConnectorError(
                "Token Login body_type=header_only requires login_request_headers.")
        resp = requests.post(url, headers=login_headers, verify=verify_ssl, timeout=timeout)
    else:
        user = config.get('login_username') or ''
        pw = config.get('login_password') or ''
        if not user:
            raise ConnectorError("Token Login requires Login URL and Username.")
        user_field = (config.get('login_username_field') or 'username').strip() or 'username'
        pw_field = (config.get('login_password_field') or 'password').strip() or 'password'
        resp = requests.post(url, json={user_field: user, pw_field: pw},
                             headers=login_headers, verify=verify_ssl, timeout=timeout)
    if not resp.ok:
        raise ConnectorError("Token login failed ({0}): {1}".format(resp.status_code, resp.text[:300]))
    ctype = (resp.headers.get('Content-Type') or '').lower()
    if token_path or 'json' in ctype:
        try:
            body = resp.json()
        except ValueError:
            body = resp.text
        token = _pluck(body, token_path) if token_path else (
            body if isinstance(body, str) else (
                body.get('access_token') or body.get('token') if isinstance(body, dict) else None
            )
        )
    else:
        token = resp.text.strip()
    if not token or not isinstance(token, str):
        raise ConnectorError("Token login response did not yield a token (path={0}).".format(token_path))
    return token


def _apply_auth(config, headers, query_params):
    """Mutates headers/query_params with auth material based on the configured auth_type."""
    source = config
    auth_type = (source.get('auth_type') or AUTH_NONE).strip()
    if auth_type == AUTH_NONE:
        return
    if auth_type == AUTH_BASIC:
        user = source.get('basic_username') or ''
        pw = source.get('basic_password') or ''
        b64 = b64encode('{0}:{1}'.format(user, pw).encode('utf-8')).decode('utf-8')
        headers.setdefault('Authorization', 'Basic {0}'.format(b64))
        return
    if auth_type == AUTH_BEARER:
        token = source.get('bearer_token') or ''
        headers.setdefault('Authorization', 'Bearer {0}'.format(token))
        return
    if auth_type == AUTH_API_KEY_HEADER:
        name = (source.get('api_key_header_name') or '').strip()
        value = source.get('api_key') or ''
        if not name:
            raise ConnectorError("API Key Header Name is required for 'API Key Header' auth.")
        headers.setdefault(name, value)
        return
    if auth_type == AUTH_API_KEY_QUERY:
        name = (source.get('api_key_param_name') or '').strip()
        value = source.get('api_key') or ''
        if not name:
            raise ConnectorError("API Key Query Param Name is required for 'API Key Query Param' auth.")
        query_params.setdefault(name, value)
        return
    if auth_type == AUTH_OAUTH2_CC:
        token = _oauth2_client_credentials_token(source)
        headers.setdefault('Authorization', 'Bearer {0}'.format(token))
        return
    if auth_type == AUTH_TOKEN_LOGIN:
        token = _token_login(source)
        header_name = (source.get('login_header_name') or 'X-Auth').strip() or 'X-Auth'
        prefix = source.get('login_header_prefix') or ''
        headers.setdefault(header_name, '{0}{1}'.format(prefix, token))
        return
    raise ConnectorError("Unsupported Authentication Type: {0}".format(auth_type))


# ---------------------------------------------------------------------------
# Body / response shape
# ---------------------------------------------------------------------------

def _prepare_body(body_type, body):
    """Returns (data, json_payload, files) tuple suitable for requests.request kwargs."""
    body_type = (body_type or 'none').strip().lower()
    if body in (None, ''):
        return None, None, None
    if body_type in ('none',):
        return None, None, None
    if body_type == 'json':
        if isinstance(body, str):
            try:
                body = _json.loads(body)
            except ValueError:
                raise ConnectorError("Body Type is 'json' but body is not valid JSON.")
        return None, body, None
    if body_type == 'form':
        return _to_dict(body), None, None
    if body_type in ('raw', 'text'):
        if isinstance(body, (dict, list)):
            body = _json.dumps(body)
        return body, None, None
    if body_type == 'multipart':
        # Expect a dict of {field_name: value_or_file_descriptor}.
        return None, None, _to_dict(body)
    raise ConnectorError("Unsupported Body Type: {0}".format(body_type))


_DOT_PATH_RE = re.compile(r'([^\.\[\]]+)|\[(\d+)\]')


def _pluck(obj, path):
    """Navigate a JSON object via a dot/bracket path: 'data.results[0].id'."""
    if not path:
        return obj
    cur = obj
    for key, idx in _DOT_PATH_RE.findall(path):
        if idx != '':
            try:
                cur = cur[int(idx)]
            except (KeyError, IndexError, TypeError):
                return None
        else:
            if isinstance(cur, dict):
                cur = cur.get(key)
            else:
                return None
        if cur is None:
            return None
    return cur


def _parse_response(response, response_path=None, raw=False):
    if raw:
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content_base64': b64encode(response.content).decode('ascii') if response.content else '',
        }
    ctype = (response.headers.get('Content-Type') or '').lower()
    if response.content and 'json' in ctype:
        try:
            body = response.json()
        except ValueError:
            body = response.text
    elif response.content and ('text/' in ctype or 'xml' in ctype or 'html' in ctype):
        body = response.text
    elif response.content:
        body = {'_binary': True, 'content_base64': b64encode(response.content).decode('ascii')}
    else:
        body = None
    if response_path and isinstance(body, (dict, list)):
        body = _pluck(body, response_path)
    return {
        'status_code': response.status_code,
        'headers': dict(response.headers),
        'body': body,
    }


# ---------------------------------------------------------------------------
# Session w/ retry
# ---------------------------------------------------------------------------

def _build_session(config):
    max_retries = int(config.get('max_retries') or 0)
    if max_retries <= 0:
        return requests.Session()
    backoff = float(config.get('backoff_factor') or 0.5)
    retry_statuses_raw = config.get('retry_on_status') or '429,500,502,503,504'
    if isinstance(retry_statuses_raw, str):
        retry_statuses = tuple(int(x.strip()) for x in retry_statuses_raw.split(',') if x.strip().isdigit())
    elif isinstance(retry_statuses_raw, list):
        retry_statuses = tuple(int(x) for x in retry_statuses_raw if str(x).isdigit())
    else:
        retry_statuses = (429, 500, 502, 503, 504)
    retry = Retry(
        total=max_retries,
        backoff_factor=backoff,
        status_forcelist=retry_statuses,
        allowed_methods=frozenset(['HEAD', 'GET', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'POST', 'PATCH']),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    sess = requests.Session()
    sess.mount('http://', adapter)
    sess.mount('https://', adapter)
    return sess


# ---------------------------------------------------------------------------
# Core request
# ---------------------------------------------------------------------------

def _do_request(config, method, rest_api, query_params=None, headers=None, body_type='none',
                body=None, timeout=None, follow_redirects=True, response_path=None, raw=False):
    method = (method or 'GET').upper()
    url = _resolve_url(config, rest_api)
    headers = _to_dict(headers) if headers is not None else {}
    # Connection-level custom headers (lowest priority — per-call headers win).
    conn_headers = _to_dict(config.get('default_headers'))
    merged_headers = {**conn_headers, **headers}
    query = {}
    for k, v in _to_list_of_pairs(query_params or {}):
        query[k] = v
    _apply_auth(config, merged_headers, query)
    data, json_payload, files = _prepare_body(body_type, body)
    if json_payload is not None and 'Content-Type' not in {k.title(): v for k, v in merged_headers.items()}:
        merged_headers['Content-Type'] = 'application/json'

    verify_ssl = bool(config.get('verify_ssl', True))
    timeout = int(timeout if timeout not in (None, '', 0) else (config.get('timeout') or 60))
    session = _build_session(config)
    try:
        response = session.request(
            method=method, url=url, headers=merged_headers, params=query,
            data=data, json=json_payload, files=files, verify=verify_ssl,
            timeout=timeout, allow_redirects=bool(follow_redirects),
        )
    except requests.exceptions.SSLError:
        raise ConnectorError(SSL_VALIDATION_ERROR)
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError(CONNECTION_TIMEOUT)
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(REQUEST_READ_TIMEOUT)
    except requests.exceptions.ConnectionError as e:
        raise ConnectorError("Connection error: {0}".format(e))
    if not response.ok and not bool(config.get('return_on_error', True)):
        raise ConnectorError("HTTP {0}: {1}".format(response.status_code, response.text[:500]))
    return _parse_response(response, response_path=response_path, raw=raw)


# ---------------------------------------------------------------------------
# Per-action params
# ---------------------------------------------------------------------------

def _common_kwargs(params):
    return {
        'rest_api': params.get('rest_api'),
        'query_params': params.get('parameter'),
        'headers': params.get('header'),
        'timeout': params.get('timeout'),
        'follow_redirects': params.get('follow_redirects', True),
        'response_path': (params.get('response_path') or '').strip() or None,
        'raw': bool(params.get('raw_response')),
    }


def http_get(config, params):
    return _do_request(config, 'GET', **_common_kwargs(params))


def http_post(config, params):
    return _do_request(config, 'POST', body_type=params.get('body_type') or 'json',
                       body=params.get('data'), **_common_kwargs(params))


def http_put(config, params):
    return _do_request(config, 'PUT', body_type=params.get('body_type') or 'json',
                       body=params.get('data'), **_common_kwargs(params))


def http_patch(config, params):
    return _do_request(config, 'PATCH', body_type=params.get('body_type') or 'json',
                       body=params.get('data'), **_common_kwargs(params))


def http_delete(config, params):
    return _do_request(config, 'DELETE', body_type=params.get('body_type') or 'none',
                       body=params.get('data'), **_common_kwargs(params))


def http_head(config, params):
    return _do_request(config, 'HEAD', **_common_kwargs(params))


def http_options(config, params):
    return _do_request(config, 'OPTIONS', **_common_kwargs(params))


def _resolve_attachment_to_path(value):
    """Accept an attachment IRI, file IRI, attachment-record dict, or local file path.
    Returns (local_path, filename). Streams the file to TMP via FSR's helper."""
    if value in (None, ''):
        raise ConnectorError("Attachment / File reference is required.")
    # Local path passthrough.
    if isinstance(value, str) and (value.startswith('/') or value.startswith('./')) \
            and os.path.exists(value):
        return value, os.path.basename(value)
    # Pull @id from a record dict if that's what was passed.
    if isinstance(value, dict):
        nested_file = value.get('file')
        nested_file_iri = nested_file.get('@id') if isinstance(nested_file, dict) else None
        value = (value.get('@id') or value.get('id') or value.get('iri')
                 or nested_file_iri or (nested_file if isinstance(nested_file, str) else None))
    if not isinstance(value, str) or not value.strip():
        raise ConnectorError("Could not resolve attachment reference to a string IRI.")
    iri = value.strip()
    try:
        from connectors.cyops_utilities.builtins import download_file_from_cyops
        from connectors.cyops_utilities.crudhub import make_cyops_request
        from django.conf import settings
    except ImportError:
        raise ConnectorError("FortiSOAR runtime helpers unavailable; cannot download file.")
    # If we were given an Attachment IRI, dereference it to its underlying File IRI.
    # download_file_from_cyops resolves File records, not Attachment wrappers.
    if '/attachments/' in iri:
        try:
            rec = make_cyops_request(iri, 'GET') or {}
        except Exception as exc:
            raise ConnectorError("Failed to fetch Attachment {0}: {1}".format(iri, exc))
        file_obj = rec.get('file') if isinstance(rec, dict) else None
        file_iri = (file_obj or {}).get('@id') if isinstance(file_obj, dict) else None
        if not file_iri:
            raise ConnectorError("Attachment {0} has no file.@id to download.".format(iri))
        iri = file_iri
    info = download_file_from_cyops(iri) or {}
    raw_path = info.get('cyops_file_path') or info.get('file_path') or info.get('path') or ''
    name = info.get('filename') or info.get('name') or os.path.basename(raw_path)
    # download_file_from_cyops returns the basename; join with TMP_FILE_ROOT to get the absolute path.
    tmp_root = getattr(settings, 'TMP_FILE_ROOT', None) or '/tmp/'
    candidates = []
    if raw_path:
        candidates.append(raw_path if os.path.isabs(raw_path) else os.path.join(tmp_root, raw_path))
    if name:
        candidates.append(os.path.join(tmp_root, name))
    for p in candidates:
        if p and os.path.exists(p):
            return p, name or os.path.basename(p)
    raise ConnectorError("Resolved file not found on disk for IRI {0} (tried: {1})".format(iri, candidates))


def upload_file(config, params):
    """POST/PUT a file to an arbitrary endpoint.

    Accepts an attachment IRI, file IRI, or attachment record (any of: `attachment_id`,
    `file_iri`, or a full @id-bearing dict passed as `attachment_id`). Streams bytes —
    the 25 MB CSV never lives in playbook engine memory.

    Modes:
      - multipart (default): standard file upload (`field_name`, default `file`)
      - raw_body: send file bytes as the request body (good for S3 PUT, filebrowser, etc.)
    """
    rest_api = params.get('rest_api')
    if not rest_api:
        raise ConnectorError("Endpoint (rest_api) is required.")
    method = (params.get('method') or 'POST').upper()
    upload_mode = (params.get('upload_mode') or 'multipart').strip().lower()
    field_name = (params.get('field_name') or 'file').strip() or 'file'
    content_type = (params.get('content_type') or '').strip() or 'application/octet-stream'

    ref = params.get('attachment_id') or params.get('file_iri') or params.get('file_path')
    local_path, derived_name = _resolve_attachment_to_path(ref)
    filename = (params.get('filename') or '').strip() or derived_name
    # Support {filename} placeholder in the destination URL (e.g. /api/resources/{filename}).
    rest_api = rest_api.replace('{filename}', quote(filename, safe=''))

    url = _resolve_url(config, rest_api)
    headers = _to_dict(params.get('header'))
    conn_headers = _to_dict(config.get('default_headers'))
    merged_headers = {**conn_headers, **headers}
    query = {}
    for k, v in _to_list_of_pairs(params.get('parameter') or {}):
        query[k] = v
    _apply_auth(config, merged_headers, query)

    verify_ssl = bool(config.get('verify_ssl', True))
    timeout = int(params.get('timeout') or config.get('timeout') or 300)
    session = _build_session(config)
    follow_redirects = bool(params.get('follow_redirects', True))

    try:
        with open(local_path, 'rb') as fh:
            if upload_mode == 'raw_body':
                merged_headers.setdefault('Content-Type', content_type)
                response = session.request(
                    method=method, url=url, headers=merged_headers, params=query,
                    data=fh, verify=verify_ssl, timeout=timeout,
                    allow_redirects=follow_redirects,
                )
            else:
                extra = _to_dict(params.get('extra_fields'))
                files = {field_name: (filename, fh, content_type)}
                response = session.request(
                    method=method, url=url, headers=merged_headers, params=query,
                    data=extra, files=files, verify=verify_ssl, timeout=timeout,
                    allow_redirects=follow_redirects,
                )
    except requests.exceptions.SSLError:
        raise ConnectorError(SSL_VALIDATION_ERROR)
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError(CONNECTION_TIMEOUT)
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(REQUEST_READ_TIMEOUT)
    except requests.exceptions.ConnectionError as e:
        raise ConnectorError("Connection error: {0}".format(e))
    if not response.ok and not bool(config.get('return_on_error', True)):
        raise ConnectorError("HTTP {0}: {1}".format(response.status_code, response.text[:500]))
    out = _parse_response(
        response,
        response_path=(params.get('response_path') or '').strip() or None,
        raw=bool(params.get('raw_response')),
    )
    try:
        size = os.path.getsize(local_path)
    except OSError:
        size = None
    out['uploaded'] = {'filename': filename, 'bytes': size, 'mode': upload_mode}
    return out


def http_request(config, params):
    """Freeform HTTP call where the user picks the method."""
    method = (params.get('method') or 'GET').upper()
    return _do_request(config, method, body_type=params.get('body_type') or 'none',
                       body=params.get('data'), **_common_kwargs(params))


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="?next"?', re.IGNORECASE)


def _next_url_from_link_header(link_header, current_url):
    if not link_header:
        return None
    m = _LINK_NEXT_RE.search(link_header)
    if not m:
        return None
    next_url = m.group(1)
    if next_url.startswith('http://') or next_url.startswith('https://'):
        return next_url
    return urljoin(current_url, next_url)


def http_paginate(config, params):
    """Walks a paginated endpoint and concatenates results.

    Modes:
      - 'link_header'  → follow RFC 5988 'next' link header.
      - 'next_url_path' → next URL is at a given dot-path inside the JSON response.
      - 'page_param'   → bump a query-param page number until response_path is empty.
    """
    mode = (params.get('pagination_mode') or 'link_header').strip()
    rest_api = params.get('rest_api')
    response_path = (params.get('response_path') or '').strip() or None
    items_path = (params.get('items_path') or response_path or '').strip() or None
    next_path = (params.get('next_url_path') or '').strip() or None
    page_param = (params.get('page_param_name') or 'page').strip()
    start_page = int(params.get('start_page') or 1)
    max_pages = int(params.get('max_pages') or 50)
    method = (params.get('method') or 'GET').upper()
    body_type = params.get('body_type') or 'none'
    common = _common_kwargs(params)
    common['response_path'] = None  # we want the full body for navigating next/items

    items = []
    current_url = rest_api
    page_no = start_page
    page_count = 0
    seen_urls = set()
    query = dict(_to_list_of_pairs(common.get('query_params') or {}))
    while page_count < max_pages:
        page_query = dict(query)
        if mode == 'page_param':
            page_query[page_param] = page_no
        common_for_call = dict(common)
        common_for_call['query_params'] = page_query
        result = _do_request(config, method, rest_api=current_url, body_type=body_type,
                             body=params.get('data'),
                             **{k: v for k, v in common_for_call.items() if k != 'rest_api'})
        body = result.get('body')
        page_items = _pluck(body, items_path) if items_path else (body if isinstance(body, list) else [])
        if isinstance(page_items, list):
            items.extend(page_items)
        elif page_items is not None:
            items.append(page_items)
        page_count += 1
        # Decide next URL.
        if mode == 'link_header':
            current_url = _next_url_from_link_header(
                result.get('headers', {}).get('Link') or result.get('headers', {}).get('link'),
                _resolve_url(config, current_url),
            )
            if not current_url or current_url in seen_urls:
                break
            seen_urls.add(current_url)
            query = {}  # next URL already carries its own query
        elif mode == 'next_url_path':
            nxt = _pluck(body, next_path) if next_path else None
            if not nxt or nxt in seen_urls:
                break
            seen_urls.add(nxt)
            current_url = nxt
            query = {}
        elif mode == 'page_param':
            if not page_items:
                break
            if isinstance(page_items, list) and len(page_items) == 0:
                break
            page_no += 1
        else:
            raise ConnectorError("Unknown pagination_mode: {0}".format(mode))
    return {'items': items, 'pages_fetched': page_count, 'truncated': page_count >= max_pages}


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

def fetch_records(config, params):
    """Used by scheduled data ingestion. Calls a configured endpoint, plucks records via response_path,
    and returns them as a flat list shaped for the connector's ingest_mapping_template.
    """
    fetch_url = params.get('fetch_url') or config.get('default_fetch_url')
    response_path = (params.get('response_path') or config.get('default_response_path') or '').strip() or None
    method = (params.get('method') or 'GET').upper()
    pagination_mode = params.get('pagination_mode') or 'none'
    if pagination_mode and pagination_mode != 'none':
        return http_paginate(config, {**params, 'rest_api': fetch_url, 'method': method,
                                      'response_path': response_path, 'items_path': response_path})
    common = _common_kwargs({**params, 'rest_api': fetch_url, 'response_path': response_path})
    result = _do_request(config, method, body_type=params.get('body_type') or 'none',
                         body=params.get('data'), **common)
    body = result.get('body')
    if isinstance(body, list):
        records = body
    elif body is None:
        records = []
    else:
        records = [body]
    return {'records': records, 'count': len(records)}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def _filename_from_content_disposition(value):
    """Extract filename from a Content-Disposition header, or None."""
    if not value:
        return None
    m = re.search(r"filename\*=(?:UTF-8'')?([^;]+)", value, re.IGNORECASE)
    if m:
        from urllib.parse import unquote
        return unquote(m.group(1).strip().strip('"'))
    m = re.search(r'filename="?([^";]+)"?', value, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


def download_file(config, params):
    """GET (or any verb) a remote URL and save the response body as an FSR
    attachment. The reverse of `upload_file` — bytes stream directly from the
    HTTP response to disk; nothing is buffered through the playbook engine.

    Output mirrors the standard HTTP response (`status_code`, `headers`) plus
    a `downloaded` block:

      downloaded:
        filename:      <resolved filename>
        bytes:         <size on disk>
        attachment:    <attachment record returned by FortiSOAR>  # if create_attachment
        file_path:     <absolute path on the integration agent>   # if not creating an attachment
    """
    rest_api = params.get('rest_api')
    if not rest_api:
        raise ConnectorError("URL (rest_api) is required.")
    method = (params.get('method') or 'GET').upper()
    create_attachment = bool(params.get('create_attachment', True))
    explicit_name = (params.get('filename') or '').strip()
    display_name = (params.get('attachment_name') or '').strip()
    description = (params.get('description') or '').strip()

    url = _resolve_url(config, rest_api)
    headers = _to_dict(params.get('header'))
    conn_headers = _to_dict(config.get('default_headers'))
    merged_headers = {**conn_headers, **headers}
    query = {}
    for k, v in _to_list_of_pairs(params.get('parameter') or {}):
        query[k] = v
    _apply_auth(config, merged_headers, query)

    # Optional request body (rare for downloads but some APIs require POST).
    data, json_payload, files = _prepare_body(
        params.get('body_type') or 'none', params.get('data'))

    verify_ssl = bool(config.get('verify_ssl', True))
    timeout = int(params.get('timeout') or config.get('timeout') or 300)
    follow_redirects = bool(params.get('follow_redirects', True))
    session = _build_session(config)

    # Pick a destination. We need a file on disk before we can hand it to
    # FortiSOAR's upload helper.
    try:
        from django.conf import settings
        tmp_root = getattr(settings, 'TMP_FILE_ROOT', None) or '/tmp/'
    except ImportError:
        tmp_root = '/tmp/'
    if not os.path.isdir(tmp_root):
        os.makedirs(tmp_root, exist_ok=True)

    try:
        response = session.request(
            method=method, url=url, headers=merged_headers, params=query,
            data=data, json=json_payload, files=files, verify=verify_ssl,
            timeout=timeout, allow_redirects=follow_redirects, stream=True,
        )
    except requests.exceptions.SSLError:
        raise ConnectorError(SSL_VALIDATION_ERROR)
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError(CONNECTION_TIMEOUT)
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(REQUEST_READ_TIMEOUT)
    except requests.exceptions.ConnectionError as e:
        raise ConnectorError("Connection error: {0}".format(e))

    if not response.ok and not bool(config.get('return_on_error', True)):
        body_preview = ''
        try:
            body_preview = response.text[:500]
        except Exception:
            pass
        raise ConnectorError("HTTP {0}: {1}".format(response.status_code, body_preview))

    # Resolve filename: explicit > Content-Disposition > URL basename > fallback.
    resolved_name = explicit_name \
        or _filename_from_content_disposition(response.headers.get('Content-Disposition')) \
        or os.path.basename(urlparse(response.url).path) \
        or 'download.bin'
    # Strip any path separators that snuck in.
    resolved_name = os.path.basename(resolved_name) or 'download.bin'
    dest_path = os.path.join(tmp_root, resolved_name)

    bytes_written = 0
    try:
        with open(dest_path, 'wb') as fh:
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                fh.write(chunk)
                bytes_written += len(chunk)
    finally:
        response.close()

    out = {
        'status_code': response.status_code,
        'headers': dict(response.headers),
    }
    downloaded = {'filename': resolved_name, 'bytes': bytes_written}

    if create_attachment:
        try:
            from connectors.cyops_utilities.builtins import upload_file_to_cyops
        except ImportError:
            raise ConnectorError(
                "FortiSOAR runtime helpers unavailable; cannot create attachment. "
                "Set 'create_attachment' to false to keep the file at {0}.".format(dest_path))
        attach = upload_file_to_cyops(
            file_path=resolved_name,
            filename=resolved_name,
            create_attachment=True,
            name=display_name or resolved_name,
            description=description or 'Downloaded via HTTP connector from {0}'.format(url),
        )
        downloaded['attachment'] = attach
    else:
        downloaded['file_path'] = dest_path

    out['downloaded'] = downloaded
    return out


def check_health(config):
    try:
        url = _build_base_url(config)
        if not url:
            # No server URL configured — accept this as healthy (connector is meant to be used
            # with absolute URLs per call).
            return True
        verify_ssl = bool(config.get('verify_ssl', True))
        timeout = int(config.get('timeout') or 30)
        resp = requests.get(url, verify=verify_ssl, timeout=timeout)
        return resp.ok or resp.status_code in (401, 403, 404)
    except requests.exceptions.SSLError:
        raise ConnectorError(SSL_VALIDATION_ERROR)
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError(CONNECTION_TIMEOUT)
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(REQUEST_READ_TIMEOUT)
    except Exception as err:
        raise ConnectorError(str(err))


http_ops = {
    'http_get': http_get,
    'http_post': http_post,
    'http_options': http_options,
    'http_put': http_put,
    'http_head': http_head,
    'http_delete': http_delete,
    'http_patch': http_patch,
    'http_request': http_request,
    'http_paginate': http_paginate,
    'fetch_records': fetch_records,
    'upload_file': upload_file,
    'download_file': download_file,
}
