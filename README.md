# pam-oidc

## Example

In `/etc/pam.d/ssh`:

```
auth requisite pam-oidc.so <options>
```

Example for Google:

```
auth requisite pam-oidc.so issuer=https://accounts.google.com auth requisite issuer=https://accounts.google.com client_id=foobar client_secret=secret
```

## References

1. https://documentation.suse.com/sles/15-SP5/html/SLES-all/cha-pam.html