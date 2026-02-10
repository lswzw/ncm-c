FROM ubuntu:20.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies and MinGW-w64 for cross-compilation
RUN apt-get update && apt-get install -y \
    cmake \
    make \
    gcc \
    g++ \
    mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Build for Linux
RUN mkdir -p build/linux && \
    cd build/linux && \
    cmake ../.. && \
    make && \
    mv ncm ncm-linux

# Build for Windows (Cross-compilation)
RUN mkdir -p build/windows && \
    cd build/windows && \
    cmake -DCMAKE_SYSTEM_NAME=Windows \
          -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
          -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
          ../.. && \
    make && \
    mv ncm.exe ncm-windows.exe
