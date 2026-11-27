# Stage 1: Build the C application
FROM debian:bookworm-slim AS builder

# Install compiler, make, and required OpenSSL/crypt headers
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    libssl-dev \
    libcrypt-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy your project files into the container
WORKDIR /app
COPY . .

# Compile the binary using your Makefile
RUN make

# Stage 2: Create a lightweight runtime image
FROM debian:bookworm-slim

# Install only the runtime libraries
RUN apt-get update && apt-get install -y \
    libssl3 \
    libcrypt1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only the compiled executable from the builder stage
COPY --from=builder /app/password_manager .

# Run the password manager when the container starts
ENTRYPOINT ["./password_manager"]
