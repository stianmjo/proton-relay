FROM python:3.12-slim

# Install pass-cli
ARG PASS_CLI_VERSION=latest
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://proton.me/download/pass-cli/install.sh | sh

# Install Python deps
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# pass-cli needs a writable home for session data
RUN useradd -m bridge
USER bridge
ENV HOME=/home/bridge

EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]