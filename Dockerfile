# Hospital SOC Alert System - container image (runs as a non-root user).
# The official python image is published for linux/s390x, so this builds natively on LinuxONE.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN useradd --create-home --uid 10001 soc
COPY requirements.txt .
RUN pip install --prefer-binary -r requirements.txt
COPY soc ./soc
COPY data/assets.csv ./assets/assets.csv
RUN mkdir -p /app/data && chown -R soc:soc /app/data
USER soc
ENV SOC_HOST=0.0.0.0 SOC_PORT=8000 SOC_DB_PATH=/app/data/soc.db SOC_ASSETS_PATH=/app/assets/assets.csv
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status == 200 else 1)"
CMD ["python", "-m", "uvicorn", "soc.asgi:app", "--host", "0.0.0.0", "--port", "8000"]
