FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends arping arp-scan iputils-ping iproute2 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
ENV DB_PATH=/data/lan-hosts.db PORT=8088 HOST=0.0.0.0
VOLUME /data
CMD ["sh", "-c", "exec uvicorn app.main:app_factory --factory --host ${HOST} --port ${PORT}"]
