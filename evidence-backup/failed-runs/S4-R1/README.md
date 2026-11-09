# S4/R1 first attempt (FAILED)

This first attempt failed validation because `transform_telemetry.suricata_c1`
did not pseudonymise the nested `flow.src_ip`/`flow.dest_ip` embedded in Suricata
alert events, so raw IPs leaked into C1. The bug was fixed (nested flow IP
handling added) and S4/R1 was re-run successfully. This archive preserves the
original failed evidence.
