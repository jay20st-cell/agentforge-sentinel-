FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENTINEL_HOST=0.0.0.0 \
    SENTINEL_PORT=8080 \
    SENTINEL_DB_PATH=/data/sentinel.db \
    SENTINEL_WEB_INDEX=/app/web/index.html

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY web ./web
RUN python -m pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 sentinel && mkdir -p /data && chown -R sentinel:sentinel /data /app
USER sentinel

VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).read()" || exit 1

CMD ["sentinel"]
