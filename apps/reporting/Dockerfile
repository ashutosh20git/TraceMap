# Report worker: pinned WeasyPrint + Pango + fonts + template bundle in one image.
FROM python:3.12.8-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 \
      fonts-inter fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY apps/reporting/requirements.txt /tmp/req.txt
RUN pip install --no-cache-dir -r /tmp/req.txt
COPY trustgate /app/trustgate
COPY report_templates /app/report_templates
COPY config /app/config
RUN useradd -m -u 10001 reporter && mkdir -p /app/reports && chown reporter /app/reports
USER reporter
ENV PYTHONUNBUFFERED=1 TRUSTGATE_SNAPSHOT=/app/data/snapshot.json TRUSTGATE_REPORTS_DIR=/app/reports
CMD ["python", "-m", "trustgate.reports.worker"]
