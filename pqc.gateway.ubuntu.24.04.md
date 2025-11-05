## 环境要求

1. **Ubuntu 24.04 amd64/arm64 测试通过**

2. 调整系统参数

   ```bash
   sudo tee /etc/sysctl.d/fs.conf <<EOF
   fs.file-max=655360
   fs.inotify.max_user_watches = 655350
   fs.inotify.max_user_instances = 1024
   EOF
   
   sudo tee /etc/security/limits.d/fs.conf <<EOF
   root    soft    nofile  65535
   root    hard    nofile  65535
   *       soft    nofile  65535
   *       hard    nofile  65535
   EOF
   ```

3. **维护伪域名**

   ```bash
   echo 127.0.0.1 a.b.example.com >> /etc/hosts
   ```

## 安装 OPENSSL 3.5.3

```bash
ARCH=$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/)
wget https://github.com/pqfif-oss/openssl/releases/download/openssl-3.5.3-ubuntu24.04/openssl-provider-legacy_3.5.3-1ubuntu2_${ARCH}.deb
wget https://github.com/pqfif-oss/openssl/releases/download/openssl-3.5.3-ubuntu24.04/libssl3t64_3.5.3-1ubuntu2_${ARCH}.deb
wget https://github.com/pqfif-oss/openssl/releases/download/openssl-3.5.3-ubuntu24.04/libssl-dev_3.5.3-1ubuntu2_${ARCH}.deb
wget https://github.com/pqfif-oss/openssl/releases/download/openssl-3.5.3-ubuntu24.04/openssl_3.5.3-1ubuntu2_${ARCH}.deb

echo "/usr/local/openssl/3.5.3/lib" | sudo tee /etc/ld.so.conf.d/openssl.conf
sudo ldconfig

sudo apt install -y \
./openssl-provider-legacy_3.5.3-1ubuntu2_${ARCH}.deb \
./libssl3t64_3.5.3-1ubuntu2_${ARCH}.deb \
./libssl-dev_3.5.3-1ubuntu2_${ARCH}.deb \
./openssl_3.5.3-1ubuntu2_${ARCH}.deb

cp /usr/local/openssl/3.5.3/lib/libcrypto.so.3 /lib/$(arch)-linux-gnu/libcrypto.so.3
cp /usr/local/openssl/3.5.3/lib/libssl.so.3 /lib/$(arch)-linux-gnu/libssl.so.3

sudo update-alternatives --install /usr/bin/openssl openssl /usr/local/openssl/3.5.3/bin/openssl 100

openssl version
```

## 制作证书

```bash
sudo mkdir /opt/certs
# 生成私钥
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out /opt/certs/a.b.example.com.key
# 生成证书签名请求 (CSR)
openssl req -new -key /opt/certs/a.b.example.com.key -out /opt/certs/a.b.example.com.csr -subj "/C=CN/ST=Liaoning/L=Dalian/O=Flomesh/OU=OSS-PQC/CN=a.b.example.com"
openssl x509 -req -in /opt/certs/a.b.example.com.csr -signkey /opt/certs/a.b.example.com.key -out /opt/certs/a.b.example.com.crt -days 365 -sha3-384

# 生成私钥
openssl genpkey -algorithm ML-DSA-44 -out /opt/certs/a.b.example.com.key
# 生成证书签名请求 (CSR)
openssl req -new -key /opt/certs/a.b.example.com.key -out /opt/certs/a.b.example.com.csr -subj "/C=CN/ST=Liaoning/L=Dalian/O=Flomesh/OU=OSS-PQC/CN=a.b.example.com"
openssl x509 -req -in /opt/certs/a.b.example.com.csr -signkey /opt/certs/a.b.example.com.key -out /opt/certs/a.b.example.com.crt -days 365 -sha3-384
```

## 安装 Curl 和 Wrk

```bash
sudo apt install -y curl wrk
```

## 安装 NGINX 1.24.0

```bash
ARCH=$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/)
wget https://github.com/pqfif-oss/nginx/releases/download/nginx-1.24.0/nginx-common_1.24.0-2ubuntu7.5_all.deb
wget https://github.com/pqfif-oss/nginx/releases/download/nginx-1.24.0/nginx_1.24.0-2ubuntu7.5_${ARCH}.deb

sudo apt install -y \
./nginx_1.24.0-2ubuntu7.5_amd64.deb \
./nginx-common_1.24.0-2ubuntu7.5_all.deb
```

## 从源码安装 PQC Gateway

```bash
sudo apt install -y build-essential cmake clang llvm-dev

git clone git@github.com:pqfif-oss/pqc-gateway.git
cd pqc-gateway
git submodule update --init
make
make install
```

## 启动 PQC NGINX 服务

```bash
sudo apt install -y php-fpm

mkdir -p /etc/nginx/sites-pqc
mkdir -p /var/www/a.b.example.com
mkdir -p /var/www/a.b.example.com.pqc

sed -i '/http {/a\\tinclude /etc/nginx/sites-pqc/a.b.example.com.conf;' /etc/nginx/nginx.conf
sed -i '/http {/a\\tinclude /etc/nginx/sites-pqc/a.b.example.com.pqc.conf;' /etc/nginx/nginx.conf
sed -i '/http {/a\\taccess_log off;' /etc/nginx/nginx.conf
sed -i '/worker_processes auto;/aworker_rlimit_nofile 65535;' /etc/nginx/nginx.conf
sed -i 's/worker_connections 768;/worker_connections 10240;/g' /etc/nginx/nginx.conf
sed -i '/events {/a\\tmulti_accept on;' /etc/nginx/nginx.conf
sed -i '/events {/a\\tuse epoll;' /etc/nginx/nginx.conf

sudo tee /etc/nginx/sites-pqc/a.b.example.com.conf <<EOF
server {
    listen 8080;
    listen [::]:8080;
    server_name a.b.example.com a.b.example.com;

    root /var/www/a.b.example.com;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

sudo tee /var/www/a.b.example.com/index.html <<EOF
Welcome to nginx!
EOF

sudo tee /etc/nginx/sites-pqc/a.b.example.com.pqc.conf <<EOF
upstream backend_http_servers { 
    server 127.0.0.1:8080; 
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name a.b.example.com;

    root /var/www/a.b.example.com.pqc;
    index index.php;

    ssl_certificate /opt/certs/a.b.example.com.crt;
    ssl_certificate_key /opt/certs/a.b.example.com.key;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ecdh_curve X25519MLKEM768;

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_param SSL_CURVE \$ssl_curve;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }

    location / {
        proxy_pass http://backend_http_servers;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

sudo tee /var/www/a.b.example.com.pqc/index.php <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL Curve Information</title>
</head>
<body>
    <h1>Your SSL Curve Information</h1>

    <?php
        \$ssl_curve = \$_SERVER['SSL_CURVE'];

        if (\$ssl_curve === '0x11ec') {
            echo "<p class='secure'>You are using X25519MLKEM768 which is post-quantum secure.</p>";
        } else {
            echo "<p class='not-secure'>You are using SSL Curve: {\$ssl_curve} which is not post-quantum secure.</p>";
        }
    ?>
</body>
</html>
EOF

systemctl restart nginx

#测试
curl -k --tlsv1.3 https://a.b.example.com
curl -v -k --tlsv1.3 https://a.b.example.com 2>&1 | grep -E 'SSL connection|Certificate level'
```

## 启动 PQC Gateway 服务

```bash
sudo tee pqc.gateway.config.yaml <<EOF
resources:
- kind: Gateway
  metadata:
    name: test
  spec:
    listeners:
      - port: 9443
        protocol: TLS
        tls:
          mode: Terminate
          pqc:
            signature: ML-DSA-44
            keyExchange: X25519MLKEM768
          certificates:
            - tls.crt: a.b.example.com.crt
              tls.key: a.b.example.com.key

- kind: TCPRoute
  spec:
    parentRefs:
      - kind: Gateway
        name: test
        port: 9443
    rules:
      - backendRefs:
        - kind: Backend
          name: test-svc

- kind: Backend
  metadata:
    name: test-svc
  spec:
    targets:
      - address: localhost
        port: 8080

secrets:
  a.b.example.com.crt: |
    -----BEGIN CERTIFICATE-----
    替换为 /opt/certs/a.b.example.com.crt 文件内容
		-----END CERTIFICATE-----
  a.b.example.com.key: |
    -----BEGIN PRIVATE KEY-----
    替换为 /opt/certs/a.b.example.com.key 文件内容
    -----END PRIVATE KEY-----
EOF

gw -c pqc.gateway.config.yaml

#测试
curl -k --tlsv1.3 https://a.b.example.com:9443 -v
curl -v -k --tlsv1.3 https://a.b.example.com:443 2>&1 | grep -E 'SSL connection|Certificate level'
```

## tls-scan

```bash
sudo apt -y update
sudo apt -y install make autoconf automake libtool pkg-config gcc unzip
sudo apt -y install libevent-dev
sudo apt -y install libgnutls28-dev

#wget https://github.com/prbinu/tls-scan/releases/download/1.6.0/tls-scan-1.6.0-linux-amd64.tar.gz

git clone git@github.com:prbinu/tls-scan.git
cd tls-scan
./build-x86-64.sh
./tls-scan -c a.b.example.com --all --pretty

export CFLAGS="-I/usr/local/openssl/3.5.3/include"
export LDFLAGS="-L/usr/local/openssl/3.5.3/lib"
autoreconf -i
./configure --prefix=${PWD}/build-root 


gcc -DPACKAGE_NAME=\"tls-scan\" -DPACKAGE_TARNAME=\"tls-scan\" -DPACKAGE_VERSION=\"1.6.0\" -DPACKAGE_STRING=\"tls-scan\ 1.6.0\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DPACKAGE=\"tls-scan\" -DVERSION=\"1.6.0\" -I.  -I./include -Wall -Wundef -Wshadow -Wunreachable-code -Wswitch-default -Wcast-align -pedantic -g -std=c99 -D_GNU_SOURCE -DTS_VERSION=\"1.6.0\" -DTS_BUILD_DATE=\"2025-10-30\" -DTS_OS=\"Linux\" -DTS_ARCH=\"x86_64\"   -I/usr/local/openssl/3.5.3/include -MT main.o -MD -MP -MF .deps/main.Tpo -c -o main.o main.c

mv -f .deps/main.Tpo .deps/main.Po


gcc -DPACKAGE_NAME=\"tls-scan\" -DPACKAGE_TARNAME=\"tls-scan\" -DPACKAGE_VERSION=\"1.6.0\" -DPACKAGE_STRING=\"tls-scan\ 1.6.0\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DPACKAGE=\"tls-scan\" -DVERSION=\"1.6.0\" -I.  -I./include -Wall -Wundef -Wshadow -Wunreachable-code -Wswitch-default -Wcast-align -pedantic -g -std=c99 -D_GNU_SOURCE -DTS_VERSION=\"1.6.0\" -DTS_BUILD_DATE=\"2025-10-30\" -DTS_OS=\"Linux\" -DTS_ARCH=\"x86_64\"   -I/usr/local/openssl/3.5.3/include -MT common.o -MD -MP -MF .deps/common.Tpo -c -o common.o common.c
mv -f .deps/common.Tpo .deps/common.Po


gcc -DPACKAGE_NAME=\"tls-scan\" -DPACKAGE_TARNAME=\"tls-scan\" -DPACKAGE_VERSION=\"1.6.0\" -DPACKAGE_STRING=\"tls-scan\ 1.6.0\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DPACKAGE=\"tls-scan\" -DVERSION=\"1.6.0\" -I.  -I./include -Wall -Wundef -Wshadow -Wunreachable-code -Wswitch-default -Wcast-align -pedantic -g -std=c99 -D_GNU_SOURCE -DTS_VERSION=\"1.6.0\" -DTS_BUILD_DATE=\"2025-10-30\" -DTS_OS=\"Linux\" -DTS_ARCH=\"x86_64\"   -I/usr/local/openssl/3.5.3/include -MT cert-parser.o -MD -MP -MF .deps/cert-parser.Tpo -c -o cert-parser.o cert-parser.c
mv -f .deps/cert-parser.Tpo .deps/cert-parser.Po


gcc -DPACKAGE_NAME=\"tls-scan\" -DPACKAGE_TARNAME=\"tls-scan\" -DPACKAGE_VERSION=\"1.6.0\" -DPACKAGE_STRING=\"tls-scan\ 1.6.0\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DPACKAGE=\"tls-scan\" -DVERSION=\"1.6.0\" -I.  -I./include -Wall -Wundef -Wshadow -Wunreachable-code -Wswitch-default -Wcast-align -pedantic -g -std=c99 -D_GNU_SOURCE -DTS_VERSION=\"1.6.0\" -DTS_BUILD_DATE=\"2025-10-30\" -DTS_OS=\"Linux\" -DTS_ARCH=\"x86_64\"   -I/usr/local/openssl/3.5.3/include -MT gnutls13.o -MD -MP -MF .deps/gnutls13.Tpo -c -o gnutls13.o gnutls13.c
mv -f .deps/gnutls13.Tpo .deps/gnutls13.Po


gcc -DPACKAGE_NAME=\"tls-scan\" -DPACKAGE_TARNAME=\"tls-scan\" -DPACKAGE_VERSION=\"1.6.0\" -DPACKAGE_STRING=\"tls-scan\ 1.6.0\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DPACKAGE=\"tls-scan\" -DVERSION=\"1.6.0\" -I.  -I./include -Wall -Wundef -Wshadow -Wunreachable-code -Wswitch-default -Wcast-align -pedantic -g -std=c99 -D_GNU_SOURCE -DTS_VERSION=\"1.6.0\" -DTS_BUILD_DATE=\"2025-10-30\" -DTS_OS=\"Linux\" -DTS_ARCH=\"x86_64\"   -I/usr/local/openssl/3.5.3/include -MT proto-adapters.o -MD -MP -MF .deps/proto-adapters.Tpo -c -o proto-adapters.o proto-adapters.c
mv -f .deps/proto-adapters.Tpo .deps/proto-adapters.Po


gcc  -I/usr/local/openssl/3.5.3/include  -L/usr/local/openssl/3.5.3/lib -o tls-scan main.o common.o cert-parser.o gnutls13.o proto-adapters.o /usr/local/openssl/3.5.3/lib/libssl.a /usr/local/openssl/3.5.3/lib/libcrypto.a /usr/lib/x86_64-linux-gnu/libevent.a /usr/lib/x86_64-linux-gnu/libevent_openssl.a /usr/lib/x86_64-linux-gnu/libgnutls.a /usr/lib/x86_64-linux-gnu/libhogweed.a /usr/lib/x86_64-linux-gnu/libnettle.a  -ldl -lrt
~                                                               



gcc  -I/usr/local/openssl/3.5.3/include  -L/usr/local/openssl/3.5.3/lib -o tls-scan main.o common.o cert-parser.o gnutls13.o proto-adapters.o  -ldl -lrt -lgnutls -levent -lssl -lnettle -lcrypto                                                                                                            
```

## 压力测试

### Nginx

```bash
wrk -t1 -c2000 -d30s https://a.b.example.com:443
```

### PQC Gateway

```bash
wrk -t1 -c2000 -d30s https://a.b.example.com:9443


while true; do
	wrk -t1 -c2000 -d60s https://a.b.example.com:9443
	sleep 60
done

pidstat -p 1060 -r 60 > gw.mem
```

