FROM python:3.12-slim
# Raw sockets for ARP without running as root: file capability on the two ARP tools only.
RUN apt-get update && apt-get install -y --no-install-recommends arping arp-scan iputils-ping iproute2 libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw+ep "$(command -v arping)" \
    && setcap cap_net_raw+ep "$(command -v arp-scan)" \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir /data && chown app:app /data
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
ENV DB_PATH=/data/lan-hosts.db PORT=8088 HOST=0.0.0.0 ROOT_PATH="" PYTHONDONTWRITEBYTECODE=1
VOLUME /data
USER 10001
CMD ["sh", "-c", "exec uvicorn app.main:app_factory --factory --host ${HOST} --port ${PORT} --root-path \"${ROOT_PATH}\""]
