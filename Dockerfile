FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        libpam-modules \
        openssh-server \
        passwd \
        procps \
        tini \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app /data /run/sshd

COPY panel.py /app/panel.py
COPY sshd_config /etc/ssh/sshd_config

RUN chmod 0755 /app/panel.py \
    && chmod 0600 /etc/ssh/sshd_config

EXPOSE 22 8080

VOLUME ["/data"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "/app/panel.py"]
