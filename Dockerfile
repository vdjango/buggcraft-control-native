FROM debian:trixie-slim AS development
RUN apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=30 update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build libboost-dev libboost-system-dev \
    libssl-dev libpq-dev libsimdjson-dev nlohmann-json3-dev libcurl4-openssl-dev \
    python3 python3-cryptography python3-requests postgresql \
    ca-certificates pkg-config clang-format && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace

FROM development AS builder
COPY . .
RUN cmake -S . -B /tmp/build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /tmp/build --parallel 2 && ctest --test-dir /tmp/build --output-on-failure
RUN cmake --install /tmp/build --prefix /opt/control

FROM debian:trixie-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libboost-system-dev libssl-dev libpq-dev libsimdjson-dev libcurl4t64 ca-certificates \
    && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 control
COPY --from=builder /opt/control /opt/control
USER 10001
ENTRYPOINT ["/opt/control/bin/buggcraft-control", "--config", "/run/control/config.json"]
