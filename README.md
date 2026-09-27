# nse

Various NSE (Nmap Scripting Engine) scripts.

## Scripts

### netscaler-id.nse

Attempts to fingerprint a Citrix NetScaler's Packet Processing Engine (NSPPE)
TCP/IP stack on virtual IP addresses (VIPs) and other interfaces, by
analyzing the behavior of the server's TCP Initial Sequence Number (ISN)
generation and its ~120-second secret rotation interval.

**Requirements**

- Nmap run in **privileged mode** (raw socket access), e.g. as root or with
  `CAP_NET_RAW`.
- Target must be reachable over **IPv4** (IPv6 is not supported).
- No source port translation between you and the target (e.g. no NAT
  rewriting source ports along the path), since the script correlates
  replies to specific source ports it sent from.
- Works against ports running `ssh`, `http`, or `https` by default
  (`22`, `80`, `443`), or any port explicitly passed with `-p`.

**Usage**

```bash
sudo nmap --privileged --script netscaler-id.nse -p 22,80,443 <target>
```

To scan a custom port not in the default service list:

```bash
sudo nmap --privileged --script netscaler-id.nse -p 8443 <target>
```

**Runtime**

The script is slow by design: it needs to observe the target across the
NetScaler's TCP ISN secret rotation window, so a full run against a single
host can take roughly **2–4 minutes** depending on timing. Use `-v -v`
(`stdnse.verbose(2, ...)`) for progress output while it waits.

**Output**

On a positive match, the script reports a confidence level:

```
Possible NetScaler PPE TCP/IP stack detected (medium confidence)
```

or, with a high-TTL VIP and TCP timestamps enabled on the target:

```
Possible NetScaler PPE TCP/IP stack (with timestamps enabled) detected (high confidence)
```

If the target's behavior is inconclusive, or replies are lost to packet
loss/network conditions, the script exits silently with no output.

**Author:** Maxim Suhanov (CICADA8)
**License:** Same as Nmap — see https://nmap.org/book/man-legal.html
