# ping_rtt overflow

## Summary

A crafted ICMP Echo Reply can trigger a signed 64‑bit integer overflow in GNU `ping`’s RTT calculation. By forging the timestamp field in the ICMP payload to be sufficiently large, the multiplication of seconds by 1,000,000 exceeds the signed `long` range, causing undefined behavior. Under AddressSanitizer (ASan), this is detected as a runtime error. In production builds it wraps silently and clamps to zero, resulting in repeated zero-RTT readings.

## Affected Versions

- iputils `ping` from the current `master` branch: https://github.com/iputils/iputils/tree/master
- Ubuntu package version: `iputils-ping 3:20240117-1build1`

## Environment

- Distribution: Ubuntu 24.04.1 LTS (Noble Numbat)
- Kernel: 5.15.167.4-microsoft-standard-WSL2
- Architecture: x86_64

## Steps to Reproduce

1. Check out the `master` branch of iputils and build with ASan:
   ```sh
   git clone https://github.com/iputils/iputils.git
   cd iputils
   mkdir builddir-asan && cd builddir-asan
   meson .. -Denable-sanitizers=true
   ninja
   ```
2. In one terminal, start the PoC listener script (`poc.py`):
   ```sh
   sudo ./poc.py
   ```
3. In another terminal, run ping:
   ```sh
   sudo ./ping/ping -R -s 64 127.0.0.1
   ```
   <img width="913" alt="{95F6857F-1E02-4CBD-9DC0-6B553C776DD9}" src="https://github.com/user-attachments/assets/c1e4a7f7-06bd-4589-9f63-e0b78a950fb8" />

4. Observe signed‐integer‐overflow errors from ASan:
   ```
   ../ping_common.c:757: runtime error: signed integer overflow
   ```
5. Without sanitizers, observe `time=0.000 ms` on every reply despite real latency.
6. In normal (non-sanitized) ping builds, note truncated replies, duplicate packets, and zero-RTT readings in the summary statistics.

## Root Cause Analysis

In `ping_common.c`, the code does:

```c
/* normalize recv_time - send_time */
tvsub(&tv, &tmp_tv);
/* compute microseconds */
triptime = tv.tv_sec * 1000000 + tv.tv_usec;
```

Because `tv.tv_sec` is a signed 64-bit `long` and attacker controls it via the ICMP payload, multiplying by 1,000,000 can exceed `LONG_MAX`, causing signed overflow (CWE-190). The code does not check for overflow before or after the multiplication.

## Proposed Fix

Modify the RTT computation to use a 128‑bit intermediate and clamp:

```diff
--- a/ping_common.c
+++ b/ping_common.c
@@ gather_statistics() {
-    triptime = tv.tv_sec * 1000000 + tv.tv_usec;
+    __int128 delta = (__int128)tv.tv_sec * 1000000 + tv.tv_usec;
+    if (delta < 0) {
+        triptime = 0;
+    } else if (delta > LLONG_MAX) {
+        triptime = LONG_MAX;
+    } else {
+        triptime = (long)delta;
+    }
```

Signed by Mohamed Maatallah
