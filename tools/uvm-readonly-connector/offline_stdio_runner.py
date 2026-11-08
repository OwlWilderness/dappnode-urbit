"""Test-only launcher: an audit guard prohibits every network operation."""
import http.client
import socket
import ssl
import sys
from pathlib import Path

def no_network(event, args):
    if event in ('socket.connect', 'socket.getaddrinfo', 'socket.bind', 'socket.sendto'):
        raise AssertionError('Network forbidden in offline stdio test.')

sys.addaudithook(no_network)
from mcp_stdio import Protocol, configured_status, serve
raise SystemExit(serve(sys.stdin.buffer, sys.stdout.buffer, Protocol(configured_status)))
