FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install OPA binary for fallback/local execution
RUN apt-get update && apt-get install -y curl && \
    mkdir -p bin && \
    curl -L -o bin/opa https://github.com/open-policy-agent/opa/releases/download/v0.61.0/opa_linux_amd64_static && \
    chmod +x bin/opa

COPY . .

CMD ["uvicorn", "src.governor_service:app", "--host", "0.0.0.0", "--port", "8000"]
