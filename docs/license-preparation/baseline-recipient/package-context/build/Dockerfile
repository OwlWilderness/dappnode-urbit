FROM alpine@sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395 AS vere-release
# Local source-built candidate; hash only, never execute Vere.
COPY --chown=0:0 candidate/urbit /out/urbit
RUN echo '58d07af97926e04bc17184bc18f53e5fb11d84fed63bd9daf2fe4ceb04c86698  /out/urbit' | sha256sum -c - && chmod 0555 /out/urbit

FROM alpine@sha256:d56c381f961d307a21b3ca004cf1e3910f106644aefb1f43e654c8a56c4fd395
LABEL io.uvm.candidate="issue-3-amd64-curl-build-02" io.uvm.distribution-cleared="false"
# Isolated candidate: Python pin refreshed; other runtime pins retained.
RUN apk add --no-cache zlib=1.3.2-r1 python3=3.14.10-r1 openssl=3.5.9-r0 nginx=1.30.6-r0
RUN addgroup -g 10000 urbit \
    && adduser -D -H -u 10000 -G urbit urbit \
    && mkdir -p /opt/importer/web /urbit/pier /urbit/uploads /urbit/control \
    && chown -R 10000:10000 /urbit \
    && chmod 0700 /urbit /urbit/pier /urbit/uploads /urbit/control
COPY --from=vere-release /out/urbit /bin/urbit
COPY --chown=0:0 tools/browser-importer/runtime.py tools/browser-importer/managed_service.py tools/browser-importer/importer.py tools/browser-importer/archive.py tools/browser-importer/enrollment.py tools/browser-importer/backend_tls.py tools/browser-importer/server.py /opt/importer/
COPY --chown=0:0 tools/browser-importer/owner_tls.py tools/browser-importer/package_service.py tools/browser-importer/public_ingress.py /opt/importer/
COPY --chown=0:0 tools/browser-importer/web/index.html tools/browser-importer/web/style.css tools/browser-importer/web/app.mjs tools/browser-importer/web/enroll.html tools/browser-importer/web/enroll.mjs /opt/importer/web/
COPY --chown=0:0 build/volume_guard.py /opt/importer/volume_guard.py
COPY --chown=0:0 build/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY --chown=0:0 THIRD_PARTY/ /usr/share/doc/uvm/THIRD_PARTY/
COPY --chown=0:0 LICENSE.md /usr/share/doc/uvm/LICENSE.md
COPY --chown=0:0 LICENSES/GPL-3.0-only.txt /usr/share/doc/uvm/LICENSES/GPL-3.0-only.txt
COPY --chown=0:0 docs/artwork.md docs/distribution-review.md docs/notice-packaging.md /usr/share/doc/uvm/docs/
COPY --chown=0:0 build/notice-files.json /usr/share/doc/uvm/notice-files.json
RUN chmod -R a=rX /usr/share/doc/uvm
USER 10000:10000
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8443/tcp
EXPOSE 34343/udp
VOLUME /urbit
WORKDIR /opt/importer
ENTRYPOINT ["sh", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["--pier-root", "/urbit/pier", "--uploads-root", "/urbit/uploads", "--control-root", "/urbit/control", "--password-hash-file", "/urbit/control/auth.json"]
