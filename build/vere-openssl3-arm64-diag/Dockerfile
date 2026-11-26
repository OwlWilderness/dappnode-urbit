# BUILD-ONLY candidate. Use this directory as context, never the repository root.
# Requires explicit image-build authorization. Does not execute Vere.
FROM --platform=linux/arm64 alpine@sha256:e311ae748be7f56ae5cba304bc488f0786df68ee507513f654a5cc8597cffb42 AS openssl
# Full resolved build-tool closure, including transitive packages, is locked.
RUN apk add --no-cache \
    gdbm=1.26-r0 libbz2=1.0.8-r6 libcrypto3=3.5.9-r0 libexpat=2.9.0-r0 \
    libffi=3.5.2-r1 libgcc=15.2.0-r5 libncursesw=6.6_p20260516-r0 \
    libpanelw=6.6_p20260516-r0 libssl3=3.5.9-r0 libstdc++=15.2.0-r5 \
    make=4.4.1-r4 mpdecimal=4.0.1-r0 musl=1.2.6-r3 \
    ncurses-terminfo-base=6.6_p20260516-r0 perl=5.42.2-r1 python3=3.14.10-r1 \
    pyc=3.14.10-r1 python3-pyc=3.14.10-r1 python3-pycache-pyc0=3.14.10-r1 \
    readline=8.3.3-r1 sqlite-libs=3.53.4-r0 xz=5.8.4-r0 xz-libs=5.8.4-r0 zlib=1.3.2-r1
WORKDIR /recipe
COPY inputs.json candidate.py builder-apks.json Dockerfile ./
COPY diagnostic.py vere.patch spawn.patch musl.patch openssl.patch target-build.patch uvm_issue3_diag.h ./
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN mkdir /work && cp /lib/apk/db/installed /work/builder-apk-db.txt
# A completed library stage remains cacheable even when the later Vere RUN fails.
RUN python3 candidate.py --openssl-only --output /work/openssl-cache

FROM openssl AS builder
# Declared only here: fresh IDs invalidate Vere, not the completed OpenSSL layer.
# A supervisor must also record/consume one fresh owner-authorized attempt locally.
ARG UVM_BUILD_ATTEMPT_ID
RUN test -n "$UVM_BUILD_ATTEMPT_ID" && \
    python3 candidate.py --build --output /work/attempt \
    --input-dir /work/openssl-cache/materials --openssl-cache /work/openssl-cache \
    --attempt-id "$UVM_BUILD_ATTEMPT_ID"

# Export public build evidence and complete build inputs, not an installable UVM image.
FROM scratch AS evidence
COPY --from=builder /work/attempt/delivery/ /
