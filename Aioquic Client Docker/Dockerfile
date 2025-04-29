FROM python:3.9-slim-bullseye
# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    openssl \
    ca-certificates \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*
# Upgrade pip
RUN python -m pip install --upgrade pip
# Clone the aioquic repository
RUN git clone https://github.com/aiortc/aioquic.git /aioquic
# Set the working directory
WORKDIR /opt
RUN git clone https://github.com/aiortc/aioquic.git && \
    cd aioquic && \
    pip install -e . && \
    pip install --no-cache-dir wsproto && \
    pip install --no-cache-dir starlette && \
    pip install --no-cache-dir uvicorn && \
    pip install --no-cache-dir Jinja2
COPY minimal_http_client.py /opt/minimal_http_client.py
COPY ssl_cert.pem /opt/ssl_cert.pem
COPY ssl_key.pem /opt/ssl_key.pem

# Expose ports 4433 and 12345
EXPOSE 4433/udp 4433/tcp
EXPOSE 12345/udp 12345/tcp
CMD ["/bin/bash"]
