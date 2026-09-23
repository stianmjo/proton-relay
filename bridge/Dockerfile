FROM python:3.12-slim

# Install pass-cli via direct binary download
ENV PASS_CLI_VERSION=2.4.1
ENV PASS_CLI_HASH=f4188430466e0a3d668b56791a8b430162cb20ceb108fed4fdbfcfe77d3080e6

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fsSL "https://proton.me/download/pass-cli/${PASS_CLI_VERSION}/pass-cli-linux-x86_64" \
         -o /usr/local/bin/pass-cli && \
    echo "${PASS_CLI_HASH}  /usr/local/bin/pass-cli" | sha256sum -c - && \
    chmod +x /usr/local/bin/pass-cli

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN groupadd -g 1000 bridge && useradd -m -u 1000 -g 1000 bridge
USER 1000:1000
ENV HOME=/home/bridge

EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
