FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Cloud Run sets $PORT at runtime (defaults to 8080); bind to it explicitly
# rather than hardcoding, so this also works unchanged if Cloud Run's default
# ever changes.
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
