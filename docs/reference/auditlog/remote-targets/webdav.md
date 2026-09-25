---
description: Configure a WebDAV remote target for sealed audit-log segments.
---

# WebDAV

The WebDAV target stores sealed segments below an existing HTTPS collection. Bifröst creates one child collection per producer and writes objects as `<endpoint>/<producer-id>/<sealed-segment-file>`. The server must support atomic same-collection moves without overwriting existing objects.

## Properties

<<property("name", "string", required=True, heading=3)>>
The unique, path-safe name of this target within the audit log.

<<property("type", "string", default="webdav", required=True, heading=3)>>
Selects the WebDAV target implementation. The aliases `web-dav` and `web_dav` are accepted; Bifröst writes the canonical value `webdav`.

<<property("publishAttemptTimeout", "duration", default="2m", heading=3)>>
Positive deadline for hashing, upload and read-back verification. Timeout cancels in-flight requests. If a temporary object may exist, Bifröst makes **one cleanup attempt** under a separate five-second deadline before retry backoff.

<<property("endpoint", "URL", "../../data-type.md#url", required=True, heading=3)>>
Existing collection as an absolute HTTPS URL. No user information, query, fragment, relative components or encoded path separators. A missing trailing slash is normalized; additional CAs use `SSL_CERT_FILE`.

<<property("username", "string", default="", heading=3)>>
Optional HTTP Basic username, supporting a string template. Configure with `password`, or omit both for anonymous access. The rendered username must be non-empty and contain no colon or control character.

<<property("password", "string", default="", heading=3)>>
Optional HTTP Basic password, supporting a string template. Configure with `username`; both rendered values must be non-empty. Prefer an environment variable or `file` template over plaintext YAML.

Credential template results are not trimmed. Basic authentication forbids control characters, so password files must not contain a trailing newline.

## Publication

* Upload under a deterministic `.bifroest-upload-*.tmp` name, verify via `GET`, then publish with atomic `MOVE` and `Overwrite: F`. Final content is **never overwritten**.
* Retries reuse a matching temporary object; an invalid one is deleted by its exact name and uploaded again later. An existing final object is accepted only after **size and SHA-256** match; any associated temporary object is cleaned up.
* Servers must support `MKCOL`, conditional `PUT`, `GET`, atomic `MOVE` and `DELETE`. Bifröst never follows redirects, lists collections or treats ETags as checksums.

## Permissions

The WebDAV account needs to create producer collections and create, read, move and delete temporary objects. It also needs to **read final objects** for conflict verification. It does **not** need listing or permission to overwrite/delete final segments. Restrict access to the configured collection where possible.

## Example

```yaml
auditlog:
  - enabled: true
    targets:
      - name: webdav-archive
        type: webdav
        endpoint: https://dav.example.com/audit/
        username: '{{ env `WEBDAV_USERNAME` }}'
        password: '{{ file `/run/secrets/webdav-password` }}'
```
