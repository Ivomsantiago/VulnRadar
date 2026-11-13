FROM node:25-bookworm-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370 AS web
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ARG INCLUDE_SAST=0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/backend
WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
RUN if [ "$INCLUDE_SAST" = "1" ]; then python -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.184.0; fi
ENV PATH="/opt/semgrep/bin:${PATH}"
COPY backend/ /app/backend/
COPY rules/ /app/rules/
COPY --from=web /build/frontend/dist /app/frontend/dist
RUN useradd --uid 10001 --create-home radar && mkdir /app/data && chown radar:radar /app/data
USER radar
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"
CMD ["sh", "-c", "python -m app.migration_runner && exec python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --no-access-log"]
