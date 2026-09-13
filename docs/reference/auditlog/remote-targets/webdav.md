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
Maximum duration of one publication attempt, including local hashing, upload, and read-back verification. The value must be positive. A timeout cancels in-flight requests. If a temporary object may have been created, Bifröst makes one deletion attempt with a fresh context bounded to five seconds before entering the coordinator's retry backoff.

<<property("endpoint", "URL", "../../data-type.md#url", required=True, heading=3)>>
The existing WebDAV collection. It must be an absolute HTTPS URL without user information, query, fragment, relative path components, or encoded path separators. Bifröst normalizes a missing trailing slash. Additional CAs can be supplied through Bifröst's `SSL_CERT_FILE` handling.

<<property("username", "string", default="", heading=3)>>
Optional HTTP Basic username. This value supports Bifröst string templates without a context object. Configure it together with `password`; omitting both selects anonymous access. The rendered username must be non-empty and cannot contain a colon or control character.

<<property("password", "string", default="", heading=3)>>
Optional HTTP Basic password. This value supports Bifröst string templates without a context object. Configure it together with `username`; both rendered values must be non-empty. Prefer an environment variable or the `file` template function over storing it directly in YAML.

Credential template results are not trimmed. Basic authentication forbids control characters, so password files must not contain a trailing newline.

## Publication

Bifröst uploads each segment under a deterministic temporary name derived from its final path, verifies it through `GET`, and exposes it with `MOVE` and `Overwrite: F`. Retries resume a matching temporary object; an invalid one is deleted by its exact name and uploaded again on a later attempt. Existing final objects are accepted only when size and SHA-256 checksum match, and their associated temporary object is cleaned up. Final content is never overwritten.

Compatible servers must support `MKCOL`, conditional `PUT`, `GET`, atomic `MOVE`, and `DELETE`. Bifröst does not follow redirects, list collections, or use ETags as checksums. A hidden `.bifroest-upload-*.tmp` object left by an interrupted attempt is recovered by the next retry.

## Permissions

The WebDAV account needs permission to create the producer collection and to create, read, move, and delete objects below it. It does not need permission to list the endpoint collection or overwrite and delete final segment objects. Restrict the account to the configured endpoint collection whenever the server supports path-scoped authorization.

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
