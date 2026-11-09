#!/bin/sh
# PP-NSMF S4 authentication responder (Basic auth, synthetic test account).
#
# Serves HTTP Basic authentication on the Alpine server node via BusyBox nc:
#
#     nc -lk -p 8080 -e /tmp/auth_responder.sh
#
# The only accepted credential is the synthetic test account below. All
# experiment traffic uses deliberately invalid credentials; the correct
# credential is never transmitted and is not a real password.

# Drain the request line and headers, capturing the Authorization header.
IFS= read -r request_line 2>/dev/null || exit 0
auth=""
while IFS= read -r line 2>/dev/null; do
    line=$(printf '%s' "$line" | tr -d '\r')
    [ -z "$line" ] && break
    case "$line" in
        [Aa]uthorization:*) auth=${line#*: } ;;
    esac
done

# base64("testuser:correct-password-123") -- synthetic test account only.
EXPECTED='Basic dGVzdHVzZXI6Y29ycmVjdC1wYXNzd29yZC0xMjM='

if [ "$auth" = "$EXPECTED" ]; then
    printf 'HTTP/1.1 200 OK\r\n'
    printf 'Content-Type: text/plain\r\n'
    printf 'Content-Length: 2\r\n'
    printf 'Connection: close\r\n'
    printf 'Server: PP-NSMF-auth\r\n'
    printf '\r\n'
    printf 'OK'
else
    printf 'HTTP/1.1 401 Unauthorized\r\n'
    printf 'WWW-Authenticate: Basic realm="pp-nsmf-test"\r\n'
    printf 'Content-Type: text/plain\r\n'
    printf 'Content-Length: 12\r\n'
    printf 'Connection: close\r\n'
    printf 'Server: PP-NSMF-auth\r\n'
    printf '\r\n'
    printf 'Unauthorized'
fi
