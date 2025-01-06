# Fetch base stage
FROM ubuntu:20.04 as base-fetch
RUN apt-get update && apt-get install -y git

# Build base stage
FROM ubuntu:20.04 as base-build
RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y build-essential pkg-config tzdata

# Fetch quiche source code
FROM base-fetch as fetch-quiche
WORKDIR /root
RUN git clone --recursive --depth 1 https://github.com/cloudflare/quiche

# Build quiche
FROM base-build as build-quiche
WORKDIR /root
RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y curl cmake tzdata \
  && curl https://sh.rustup.rs -sSf | sh -s -- -y
COPY --from=fetch-quiche /root/quiche /root/quiche
WORKDIR /root/quiche/
RUN ~/.cargo/bin/cargo build --release --features ffi,pkg-config-meta,qlog \
  && mkdir -p quiche/deps/boringssl/src/lib \
  && ln -vnf $(find target/release -name libcrypto.a -o -name libssl.a) quiche/deps/boringssl/src/lib/

# Fetch curl source code and other required files
FROM base-fetch as fetch-curl
WORKDIR /root
COPY http3-flood.sh /tmp/http3-flood.sh
RUN mv /tmp/http3-flood.sh /root/http3-flood.sh
RUN touch /root/sslkeylog.log
RUN git clone --depth 1 https://github.com/curl/curl

# Build curl with quiche
FROM base-build as build-curl
RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y autoconf libtool libpsl-dev
COPY --from=fetch-curl /root/curl /root/curl
WORKDIR /root/curl
RUN ./buildconf
COPY --from=build-quiche /root/quiche /root/quiche
RUN ./configure LDFLAGS="-Wl,-rpath,$PWD/../quiche/target/release" \
  --with-openssl=$PWD/../quiche/quiche/deps/boringssl/src \
  --with-quiche=$PWD/../quiche/target/release \
  --with-ca-path=/etc/ssl/certs || { cat config.log; exit 1; }
RUN make -j$(nproc)
RUN make install

# Final executor stage
FROM ubuntu:20.04 as executor
RUN apt update && apt install -y --no-install-recommends ca-certificates libpsl5 && rm -rf /var/lib/apt/lists/*
COPY --from=build-curl /etc/ld.so.conf.d/libc.conf /etc/ld.so.conf.d/libcurl.conf
COPY --from=build-curl /usr/local/lib/libcurl.so.4 /usr/local/lib/libcurl.so.4
COPY --from=build-curl /etc/ld.so.conf.d/libc.conf /etc/ld.so.conf.d/libquiche.conf
COPY --from=build-curl /root/quiche/target/release/libquiche.so /usr/local/lib/libquiche.so
COPY --from=build-curl /usr/local/bin/curl /usr/local/bin/curl
RUN ldconfig
CMD ["bash"]

