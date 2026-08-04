FROM python:3.12-slim

LABEL description="Mistral AI agent test client with SPIFFE/SPIRE identity"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy test script
COPY test_spiffe_identity.py ./

# Run as non-root to demonstrate unix workload attestation by UID
RUN useradd -u 1000 -m mistral
USER mistral

CMD ["python", "test_spiffe_identity.py"]
