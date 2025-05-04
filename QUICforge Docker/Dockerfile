# Use an official Python 3 base image
FROM python:3.9-slim

# Install system dependencies including required tools for BoringSSL and lsquic.
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    cmake \
    libssl-dev \
    pkg-config \
    iptables \ 
    libnetfilter-queue-dev \
    libpcap-dev \
    golang \
    libevent-dev \
    libz-dev \
    binutils \
 && rm -rf /var/lib/apt/lists/*

# Install Python packages: NetfilterQueue and ScaPY
RUN pip install --no-cache-dir NetfilterQueue scapy

# Set working directory for subsequent operations
WORKDIR /opt

COPY aioquic.diff /opt/aioquic.diff

# Clone the aioquic repository, checkout a specific commit, and install it.
RUN git clone https://github.com/aiortc/aioquic.git && \
    cd aioquic && \
    git checkout 7f27a0b8fd2c4ab755c5a7ba32b4d432dda305dd && \
    git apply /opt/aioquic.diff && \
    pip install -e . && \
    pip install --no-cache-dir wsproto && \
    pip install --no-cache-dir starlette && \
    pip install --no-cache-dir uvicorn && \
    pip install --no-cache-dir Jinja2

# Build BoringSSL at a specific commit.
RUN git clone https://boringssl.googlesource.com/boringssl && \
    cd boringssl && \
    git checkout a9670a8b476470e6f874fef3554e8059683e1413 && \
    cmake . && make

# Clone, build, and install lsquic from its repository using the built BoringSSL.
RUN git clone https://github.com/litespeedtech/lsquic.git && \
    cd lsquic && \
    git checkout 7686d8fcef284cda07a951ad74a5e90c69a9dfb1 && \
    git submodule update --init --recursive && \
    cmake -DBORINGSSL_DIR=/opt/boringssl . && \
    make && make install

# Clone the QUICforge repository at the end.
RUN git clone https://github.com/yurigbur/QUICforge.git

EXPOSE 4433/udp 4433/tcp
CMD ["/bin/bash"]

