"""Dependency-free wire encoding shared by the isolated worker and host binder."""
import json


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
