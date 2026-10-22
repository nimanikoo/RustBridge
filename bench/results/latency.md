# Round-trip latency (request/echo, steady state)

RTT = one request sent and echoed back, timed in the requester with CLOCK_MONOTONIC_RAW,
after warm-up. Shared memory busy-spins (low latency, high CPU); UDS blocks in the kernel.

| flow | bytes | n | p50 us | p95 us | p99 us | min us | max us | mean us | verified |
|---|---|---|---|---|---|---|---|---|---|
| shm-raw | 64 | 50000 | 0.38 | 0.67 | 0.75 | 0.12 | 15.96 | 0.41 | yes |
| shm-raw | 1024 | 50000 | 0.50 | 0.88 | 0.92 | 0.12 | 12.88 | 0.57 | yes |
| shm-raw | 65536 | 50000 | 2.04 | 2.71 | 3.17 | 1.50 | 31.62 | 2.17 | yes |
| shm-aead | 64 | 50000 | 0.33 | 0.46 | 0.71 | 0.17 | 22.04 | 0.35 | yes |
| shm-aead | 1024 | 50000 | 2.33 | 2.62 | 3.25 | 1.75 | 19.04 | 2.22 | yes |
| shm-aead | 65536 | 50000 | 106.67 | 131.21 | 137.83 | 100.12 | 405.58 | 110.05 | yes |
| uds-raw | 64 | 50000 | 4.33 | 7.54 | 8.42 | 2.92 | 34.54 | 4.92 | yes |
| uds-raw | 1024 | 50000 | 4.33 | 7.67 | 8.75 | 3.00 | 63.04 | 4.83 | yes |
| uds-raw | 65536 | 50000 | 70.58 | 79.83 | 89.75 | 39.92 | 387.25 | 71.02 | yes |
| uds-aead | 64 | 50000 | 4.33 | 7.42 | 8.54 | 3.08 | 37.54 | 4.70 | yes |
| uds-aead | 1024 | 50000 | 7.88 | 10.54 | 11.00 | 4.50 | 41.25 | 8.01 | yes |
| uds-aead | 65536 | 50000 | 177.38 | 190.75 | 206.04 | 144.96 | 1273.04 | 177.43 | yes |
