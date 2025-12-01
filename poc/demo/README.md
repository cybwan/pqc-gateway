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
   echo 127.0.0.1 gateway.example.com >> /etc/hosts
   echo 127.0.0.1 nginx.example.com >> /etc/hosts
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

## 安装 Curl

```bash
sudo apt install -y curl
```

## 部署 NGINX 服务

### 安装 NGINX

```bash
sudo apt install -y nginx
```

### 制作证书

```bash
sudo mkdir /opt/certs
# 生成私钥
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out /opt/certs/nginx.example.com.key
# 生成证书签名请求 (CSR)
openssl req -new -key /opt/certs/nginx.example.com.key -out /opt/certs/nginx.example.com.csr -subj "/C=CN/ST=Liaoning/L=Dalian/O=Flomesh/OU=OSS-PQC/CN=nginx.example.com"
openssl x509 -req -in /opt/certs/nginx.example.com.csr -signkey /opt/certs/nginx.example.com.key -out /opt/certs/nginx.example.com.crt -days 365 -sha3-384
```

### 配置 NGINX 服务

```bash
mkdir -p /etc/nginx/sites-poc
mkdir -p /var/www/nginx.example.com.441
mkdir -p /var/www/nginx.example.com.442

#access rewrite log, 记录请求头中的 Host
sed -i "/http {/a\\\taccess_log \/var\/log\/nginx\/access_rewtite.log rewtite;" /etc/nginx/nginx.conf
sed -i "/http {/a\\\tlog_format rewtite '\$remote_addr - Host:\$host';" /etc/nginx/nginx.conf

sed -i '/http {/a\\tinclude /etc/nginx/sites-poc/nginx.example.com.442.conf;' /etc/nginx/nginx.conf
sed -i '/http {/a\\tinclude /etc/nginx/sites-poc/nginx.example.com.441.conf;' /etc/nginx/nginx.conf

sed -i '/worker_processes auto;/aworker_rlimit_nofile 65535;' /etc/nginx/nginx.conf
sed -i 's/worker_connections 768;/worker_connections 10240;/g' /etc/nginx/nginx.conf
sed -i '/events {/a\\tmulti_accept on;' /etc/nginx/nginx.conf
sed -i '/events {/a\\tuse epoll;' /etc/nginx/nginx.conf

sudo tee /var/www/nginx.example.com.441/index.html <<EOF
Welcome to nginx 441 !
EOF

sudo tee /var/www/nginx.example.com.442/index.html <<EOF
Welcome to nginx 442 !
EOF

sudo tee /etc/nginx/sites-poc/nginx.example.com.441.conf <<EOF
server {
    listen 441 ssl;
    listen [::]:441 ssl;
    server_name nginx.example.com;

    ssl_certificate /opt/certs/nginx.example.com.crt;
    ssl_certificate_key /opt/certs/nginx.example.com.key;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ecdh_curve X25519;

    location / {
        root /var/www/nginx.example.com.441;
        index index.html;
    }
}
EOF

sudo tee /etc/nginx/sites-poc/nginx.example.com.442.conf <<EOF
server {
    listen 442 ssl;
    listen [::]:442 ssl;
    server_name nginx.example.com;

    ssl_certificate /opt/certs/nginx.example.com.crt;
    ssl_certificate_key /opt/certs/nginx.example.com.key;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ecdh_curve X25519;

    location / {
        root /var/www/nginx.example.com.442;
        index index.html;
    }
}
EOF

systemctl restart nginx

#测试
curl -k --tlsv1.3 https://nginx.example.com:441
curl -k --tlsv1.3 https://nginx.example.com:442
```

## 安装 FGW

### 从源码安装 FGW

```bash
sudo apt install -y build-essential cmake clang llvm-dev

git clone git@github.com:pqfif-oss/pqc-gateway.git
cd pqc-gateway
git submodule update --init
make
make install
```

### 制作证书

```bash
sudo mkdir certs

# 生成私钥
openssl genpkey -algorithm ML-DSA-44 -out certs/pqc.flomesh.io.key
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out certs/pqc.flomesh.io.key
# 生成证书签名请求 (CSR)
openssl req -new -key certs/pqc.flomesh.io.key -out certs/pqc.flomesh.io.csr -subj "/C=CN/ST=Liaoning/L=Dalian/O=Flomesh/OU=OSS-PQC/CN=pqc.flomesh.io"
openssl x509 -req -in certs/pqc.flomesh.io.csr -signkey certs/pqc.flomesh.io.key -out certs/pqc.flomesh.io.crt -days 365 -sha3-384
```

### 启动 FGW 服务

```bash
gw -c poc/demo/poc.gateway.config.yaml --debug
```

### 测试

#### PQC Termination 测试

执行如下指令:

```bash
curl -k --tlsv1.3 https://gateway.example.com:443//markets
curl -k --tlsv1.3 https://gateway.example.com:443
curl -k --tlsv1.3 https://pqc.flomesh.io:8443
```

返回:

```log
Welcome to nginx 441 !
Welcome to nginx 442 !
```

#### Host Rewrite  测试

执行如下指令:

```bash
cat /var/log/nginx/access_rewtite.log
```

返回:

```log
127.0.0.1 - Host:nginx.example.com
127.0.0.1 - Host:nginx.example.com
```

通过access_rewtite.log能看到 Host 被 rewrite 为 nginx.example.com

#### Rate Limit  测试

执行如下指令:

```bash
curl -k --tlsv1.3 https://gateway.example.com:443 -I &
curl -k --tlsv1.3 https://gateway.example.com:443 -I &
curl -k --tlsv1.3 https://gateway.example.com:443 -I &
curl -k --tlsv1.3 https://gateway.example.com:443 -I &

```

返回:

```http
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Wed, 05 Nov 2025 11:46:30 GMT
Content-Type: text/html
Content-Length: 23
Last-Modified: Wed, 05 Nov 2025 06:56:52 GMT
ETag: "690af534-17"
Accept-Ranges: bytes
connection: keep-alive

HTTP/1.1 429 Too Many Requests
foo: bar
content-length: 18
connection: keep-alive

HTTP/1.1 429 Too Many Requests
foo: bar
content-length: 18
connection: keep-alive

HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Wed, 05 Nov 2025 11:46:31 GMT
Content-Type: text/html
Content-Length: 23
Last-Modified: Wed, 05 Nov 2025 06:56:52 GMT
ETag: "690af534-17"
Accept-Ranges: bytes
connection: keep-alive
```

包含限速 429 状态码



keyExchange: X25519MLKEM768:X25519:secp384r1:prime256v1
