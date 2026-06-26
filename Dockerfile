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
  && rm -rf /var/lib/apt/lists/*

RUN groupadd -r nginx && useradd -r -g nginx nginx

COPY ./ /code/
WORKDIR /code

RUN python3 install.py install

EXPOSE 80

CMD ["/opt/verynginx/openresty/nginx/sbin/nginx", "-g", "daemon off; error_log /dev/stderr info;"]
