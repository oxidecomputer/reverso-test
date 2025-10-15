`reverso-test` detects interfaces which are **physically** looped back, such
that packets exiting the interface immediately arrive back on that interface.

Run it on an illumos machine with an interface name, e.g.

```
BRM06240009-switch # ./reverso-test gimlet27
Success: loopback detected
BRM06240009-switch # ./reverso-test gimlet2
Error: No loopback detected
```

In this system, the `gimlet27` cubby has a Reverso board installed, while
`gimlet2` does not.

The selected interface must have a link-local IPv6 unicast address.
