# pam-oidc

## Example

In `/etc/pam.d/ssh`:

```
auth requisite pam-oidc.so <options>
```

Example for Google:

```
auth requisite pam-oidc.so
```

## References

1. https://documentation.suse.com/sles/15-SP5/html/SLES-all/cha-pam.html