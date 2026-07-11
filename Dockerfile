# Reva ↔ TrueFoundry custom-guardrail plugin.
FROM python:3.12-slim

WORKDIR /app

# Install deps first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

# Single worker keeps the shared httpx.AsyncClient (and its connection pool)
# process-local; scale with replicas, not workers, so pooling stays effective.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
