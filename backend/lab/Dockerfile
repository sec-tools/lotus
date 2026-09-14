FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH=/opt/lotus-venv/bin:$PATH

# One-time install of all language runtimes and tracing/analysis tooling.
# This image is reused across repositories; only per-repo dependencies are
# installed at build time, and the runtime container has no external network.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    git \
    curl \
    wget \
    netcat-openbsd \
    tcpdump \
    strace \
    gdb \
    libvips-tools \
    imagemagick \
    libpq-dev \
    libsqlite3-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libyaml-dev \
    libmagickwand-dev \
    pkg-config \
    python3 \
    python3-venv \
    python3-pip \
    ruby \
    ruby-dev \
    ruby-bundler \
    nodejs \
    npm \
    golang-go \
    openjdk-21-jdk-headless \
    maven \
    php-cli \
    php-dev \
    php-xml \
    php-mbstring \
    php-curl \
    php-pear \
    autoconf \
    autopoint \
    && rm -rf /var/lib/apt/lists/*

# Dedicated Python venv for Lotus tooling inside the lab
RUN python3 -m venv /opt/lotus-venv && \
    /opt/lotus-venv/bin/pip install --no-cache-dir httpx

# Match the same Bundler used elsewhere
RUN gem install bundler:2.4.22

# Unprivileged lab user (use -o to allow non-unique UID, or create without fixed UID)
RUN useradd -m -s /bin/bash lotus 2>/dev/null || true
USER lotus
WORKDIR /app
