FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    libpcre3-dev \
    libssl-dev \
    zlib1g-dev \
    wget \
    perl \
    procps \
    python3 \
    nftables \
    golang-go \
    curl \
  && rm -rf /var/lib/apt/lists/*

RUN groupadd -r nginx && useradd -r -g nginx nginx

COPY ./ /code/
WORKDIR /code

RUN python3 install.py install

# Build and install the Firewall Helper (Go binary for kernel IP blocking)
RUN cd /code/helper && go build -o firewall-helper . && \
    cp firewall-helper /usr/local/bin/ && \
    chmod 755 /usr/local/bin/firewall-helper && \
    mkdir -p /run/verynginx && \
    chmod 755 /run/verynginx

# Install systemd units (for non-Docker deployments)
COPY helper/firewall-helper.socket /etc/systemd/system/
COPY helper/firewall-helper.service /etc/systemd/system/

EXPOSE 80

# In Docker, the Helper runs as a sidecar with CAP_NET_ADMIN.
# This container only runs nginx; the socket is shared via volume.
CMD ["/opt/verynginx/openresty/nginx/sbin/nginx", "-g", "daemon off; error_log /dev/stderr info;"]
