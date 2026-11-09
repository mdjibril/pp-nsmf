#!/bin/sh
# PP-NSMF S6 bulk-transfer receiver (drains and discards incoming payload).
#
# Serves a one-directional synthetic bulk transfer on the server node:
#
#     nc -lk -p 9999 -e /tmp/bulk_receiver.sh
#
# The payload is discarded; byte counts are captured by Zeek conn.log and
# Suricata flow events, not by this receiver. No payload content is stored.

cat > /dev/null
