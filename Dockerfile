FROM debian:trixie-slim AS packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    kamailio kamailio-sqlite-modules kamailio-tls-modules \
    iptables python3-yaml ca-certificates
WORKDIR /opt/sipdock
COPY sipdock.py kamailio.cfg registrations.html LICENSE.md ./
COPY build/rootfs.py /tmp/rootfs.py
RUN python3 /tmp/rootfs.py

FROM scratch
COPY --from=packages /rootfs/ /
WORKDIR /opt/sipdock
ENV PATH=/usr/sbin:/usr/bin PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt OPENSSL_CONF=/etc/ssl/openssl.cnf
LABEL org.opencontainers.image.title="SipDock" org.opencontainers.image.licenses="BlueOak-1.0.0"
EXPOSE 5060/udp 5061/tcp 8080/tcp 8081/tcp
HEALTHCHECK --interval=15s --timeout=4s --start-period=30s --retries=3 \
    CMD ["python3", "sipdock.py", "healthcheck"]
ENTRYPOINT ["python3", "sipdock.py"]
CMD ["serve"]
