#!/bin/sh
# PP-NSMF S1 HTTP responder.
#
# Serves a fixed HTML page for every request. Intended to run on the Alpine
# server node (no httpd or Python present) via BusyBox netcat:
#
#     nc -lk -p 80 -e /tmp/http_responder.sh
#
# BusyBox nc runs this program once per connection with the socket bound to
# stdin/stdout; -l with -k keeps the listener running across connections.

# Drain the request line and headers up to the terminating blank line so the
# request is fully observed by Zeek/Suricata before the response is written.
IFS= read -r request_line 2>/dev/null || exit 0
while IFS= read -r line 2>/dev/null; do
    line=$(printf '%s' "$line" | tr -d '\r')
    [ -z "$line" ] && break
done

BODY='<!DOCTYPE html>
<html><head><title>PP-NSMF</title></head>
<body><h1>PP-NSMF test page</h1><p>Hello from POC-SERVER-1.</p></body>
</html>'
LEN=${#BODY}

printf 'HTTP/1.1 200 OK\r\n'
printf 'Content-Type: text/html\r\n'
printf 'Content-Length: %d\r\n' "$LEN"
printf 'Connection: close\r\n'
printf 'Server: PP-NSMF-http\r\n'
printf '\r\n'
printf '%s' "$BODY"
