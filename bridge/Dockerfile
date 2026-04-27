FROM python:3.12-slim

# Install pass-cli via direct binary download
ENV PASS_CLI_VERSION=2.0.2
ENV PASS_CLI_HASH=fd60a5041e642a7b1135ef6878c3d7ce3523b083210ea8100eee5c3701017ed9

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fsSL "https://proton.me/download/pass-cli/${PASS_CLI_VERSION}/pass-cli-linux-x86_64" \
         -o /usr/local/bin/pass-cli && \
    echo "${PASS_CLI_HASH}  /usr/local/bin/pass-cli" | sha256sum -c - && \
    chmod +x /usr/local/bin/pass-cli

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