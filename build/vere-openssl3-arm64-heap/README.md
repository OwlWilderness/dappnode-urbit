# OpenSSL 3 system-heap hypothesis candidate

Isolated experiment, not a production-qualified fix. Same diagnostic markers and dependency versions as the failed ARM64 diagnostic; only functional change is bypassing Vere OpenSSL loom allocator installation for OpenSSL 3+. GMP remains unchanged. Normal exit/cleanup retained. Review bail/leak/accounting implications before production adoption.
