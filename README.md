# yasshd

## Example

In `/etc/pam.d/ssh`:

```
auth requisite yasshd.so <options>
```

Example for Google:

```
auth requisite yasshd.so
```

## References

1. https://documentation.suse.com/sles/15-SP5/html/SLES-all/cha-pam.html