FROM node:24-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9 AS web
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
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
