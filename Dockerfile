# Stage 1: Build the C application
FROM debian:bookworm-slim AS builder

# Compiler, make, and the OpenSSL / libcrypt development files
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    make \
    libssl-dev \
    libcrypt-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Makefile ./
COPY src ./src

# Build ./pm with the Makefile
RUN make pm

# Stage 2: Create a lightweight runtime image
FROM debian:bookworm-slim

# Runtime libraries only
RUN apt-get update && apt-get install -y \
    libssl3 \
    libcrypt1 \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user; data and backups live on two separate volumes
RUN useradd --system --create-home --uid 10001 pmuser \
    && mkdir -p /data /backups \
    && chown pmuser:pmuser /data /backups \
    && chmod 700 /data /backups

ENV PM_DATA_DIR=/data \
    PM_BACKUP_DIR=/backups

VOLUME ["/data", "/backups"]

WORKDIR /app

# Copy only the compiled executable from the builder stage
COPY --from=builder /app/pm ./pm

USER pmuser

# Start with:  docker run -it --rm -v pm-data:/data -v pm-backups:/backups <image>
ENTRYPOINT ["./pm"]
