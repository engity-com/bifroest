---
description: Configure a WebDAV remote target for sealed audit-log segments.
---

# WebDAV

!!! warning
     Remote delivery is not active in this build. See [Remote targets](index.md) for details.

The WebDAV target publishes sealed segments below a configured HTTPS collection. The collection itself must already exist. Bifröst creates one child collection per producer with `MKCOL`.

New segments are uploaded under a random temporary name in the producer collection and read back and validated before a `MOVE` with `Overwrite: F` exposes them at their final name. Existing final objects are accepted only when their exact size and SHA-256 checksum match. Conflicting content is never overwritten.

A compatible server must support `MKCOL`, conditional `PUT` with `If-None-Match: *`, `GET`, atomic same-collection `MOVE` with `Overwrite: F`, and `DELETE` for temporary-object cleanup. Bifröst does not follow redirects, perform application-level retries, or rely on ETags as content checksums. It attempts to delete the temporary object after detectable upload, verification, or publication failures. A process crash or canceled request can still leave a hidden `.bifroest-upload-*.tmp` object; stale-object retention and cleanup remain part of the remote-delivery coordinator.

Objects use the URL `<endpoint>/<producer-id>/<sealed-segment-file>`.

## Properties

<<property("name", "string", required=True, heading=3)>>
The unique, path-safe name of this target within the audit log.

<<property("type", "string", default="webdav", required=True, heading=3)>>
Selects the WebDAV target implementation. The aliases `web-dav` and `web_dav` are accepted; Bifröst writes the canonical value `webdav`.

<<property("endpoint", "URL", "../../data-type.md#url", required=True, heading=3)>>
The existing WebDAV collection. It must be an absolute HTTPS URL without user information, query, fragment, relative path components, or encoded path separators. Bifröst normalizes a missing trailing slash. Additional CAs can be supplied through Bifröst's `SSL_CERT_FILE` handling.

<<property("username", "string", default="", heading=3)>>
Optional HTTP Basic username. This value supports Bifröst string templates without a context object. Configure it together with `password`; omitting both selects anonymous access. The rendered username must be non-empty and cannot contain a colon or control character.

<<property("password", "string", default="", heading=3)>>
Optional HTTP Basic password. This value supports Bifröst string templates without a context object. Configure it together with `username`; both rendered values must be non-empty. Prefer an environment variable or the `file` template function over storing it directly in YAML.

Credential template results are not trimmed. Basic authentication forbids control characters, so password files must not contain a trailing newline.

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
