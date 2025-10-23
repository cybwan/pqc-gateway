### Ubuntu 24.04 进行后量子加密

## 安装依赖

```bash
sudo apt install -y build-essential cmake clang llvm-dev zlib1g-dev libpcre3 libpcre3-dev libpsl-dev php-fpm
```

## 从源代码安装 OpenSSL

```bash
wget https://www.openssl.org/source/openssl-3.5.4.tar.gz
tar -xzvf openssl-3.5.4.tar.gz
cd openssl-3.5.4
./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl shared zlib unzip
make
make install

echo "/usr/local/openssl/lib" | sudo tee /etc/ld.so.conf.d/openssl.conf
sudo ldconfig

cp /usr/local/openssl/lib64/libcrypto.so.3 /lib/x86_64-linux-gnu/libcrypto.so.3
cp /usr/local/openssl/lib64/libssl.so.3 /lib/x86_64-linux-gnu/libssl.so.3
ln -s /usr/local/openssl/lib64 /usr/local/openssl/lib
/usr/local/openssl/bin/openssl version

echo PATH=/usr/local/openssl/bin:\$PATH >> ~/.bashrc
source ~/.bashrc
openssl version

openssl list -tls1_3 -tls-groups
openssl list -cipher-algorithms
openssl list -cipher-commands
openssl ciphers -v
openssl list -signature-algorithms
```

## 从源安装 pqc-gateway

```bash
git clone git@github.com:cybwan/pqc-gateway.git -b bench/test
cd pqc-gateway
git submodule update --init
make
make install

gw -c examples/pqc-termination/config.yaml

curl -k --tlsv1.3 -H "Host:a.b.example.com" https://127.0.0.1:9443

openssl s_client -connect 127.0.0.1:9443 -tls1_3 -groups MLKEM768 -servername a.b.example.com

openssl s_client -connect 127.0.0.1:9443 -tls1_3 -groups X25519MLKEM768 -servername a.b.example.com
```

## 从源安装 NGINX

```bash
wget --no-check-certificate https://nginx.org/download/nginx-1.29.2.tar.gz
tar zxvf nginx-1.29.2.tar.gz
cd nginx-1.29.2

./configure --with-cc-opt='-g -O2 -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2' \
    --with-ld-opt='-Wl,-z,relro -Wl,-z,now -fPIC'    \
    --prefix=/opt                                    \
    --conf-path=/opt/nginx/nginx.conf              	 \
    --http-log-path=/var/log/nginx/access.log      	 \
    --error-log-path=/var/log/nginx/error.log      	 \
    --lock-path=/var/lock/nginx.lock               	 \
    --pid-path=/run/nginx.pid                      	 \
    --modules-path=/opt/lib/nginx/modules            \
    --http-client-body-temp-path=/var/lib/nginx/body \
    --http-fastcgi-temp-path=/var/lib/nginx/fastcgi  \
    --http-proxy-temp-path=/var/lib/nginx/proxy      \
    --http-scgi-temp-path=/var/lib/nginx/scgi        \
    --http-uwsgi-temp-path=/var/lib/nginx/uwsgi      \
    --with-compat                                  	 \
    --with-debug                                   	 \
    --with-http_ssl_module                         	 \
    --with-http_stub_status_module                 	 \
    --with-http_realip_module                      	 \
    --with-http_auth_request_module                	 \
    --with-http_v2_module                          	 \
    --with-http_dav_module                         	 \
    --with-http_slice_module                       	 \
    --with-threads                                 	 \
    --with-http_addition_module                    	 \
    --with-http_gunzip_module                      	 \
    --with-http_gzip_static_module                 	 \
    --with-http_sub_module                         	 \
    --with-pcre                                    	 \
    --with-openssl-opt=enable-tls1_3               	 \
    --with-ld-opt="-L/usr/local/openssl/lib64 -Wl,-rpath,/usr/local/openssl/lib64" \
    --with-cc-opt="-I/usr/local/openssl/include"

make
make install

mkdir /var/lib/nginx
mkdir /opt/nginx/conf.d
mkdir /opt/nginx/snippets
mkdir -p /var/www/example.com
mkdir -p /var/www/a.b.example.com

sed -i 's/#user  nobody;/user www-data;/g' /opt/nginx/nginx.conf
sed -i '/http {/a\    include       /opt/nginx/conf.d/pqc.conf;' /opt/nginx/nginx.conf
sed -i '/http {/a\    include       /opt/nginx/conf.d/a.b.example.com.conf;' /opt/nginx/nginx.conf

sudo tee /opt/nginx/conf.d/a.b.example.com.conf <<EOF
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
hello
EOF

sudo tee /opt/nginx/conf.d/pqc.conf <<EOF
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name example.com www.example.com;

    root /var/www/example.com;
    index index.php;

    ssl_certificate /opt/certs/pqc.crt;
    ssl_certificate_key /opt/certs/pqc.key;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ecdh_curve X25519MLKEM768;

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_param SSL_CURVE \$ssl_curve;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

sudo tee /opt/nginx/snippets/fastcgi-php.conf <<EOF
    # regex to split \$uri to \$fastcgi_script_name and \$fastcgi_path
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    # Check that the PHP script exists before passing it
    try_files \$fastcgi_script_name =404;
    # Bypass the fact that try_files resets \$fastcgi_path_info
    set \$path_info \$fastcgi_path_info;
    fastcgi_param PATH_INFO \$path_info;
    fastcgi_index index.php;
    include fastcgi.conf;
EOF

sudo tee /var/www/example.com/index.php <<EOF
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

        if (\$ssl_curve === 'X25519MLKEM768') {
            echo "<p class='secure'>You are using X25519MLKEM768 which is post-quantum secure.</p>";
        } else {
            echo "<p class='not-secure'>You are using SSL Curve: {\$ssl_curve} which is not post-quantum secure.</p>";
        }
    ?>

</body>
</html>
EOF

sudo mkdir /opt/certs
#sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /opt/certs/pqc.key -out /opt/certs/pqc.crt -subj "/C=CN/ST=Liaoning/L=Dalian/O=Flomesh/OU=OSS-PQC/CN=www.example.com"

# 生成私钥
openssl genpkey -algorithm rsa:2048 -out /opt/certs/pqc.key
# 生成证书签名请求 (CSR)
openssl req -new -key /opt/certs/pqc.key -out /opt/certs/pqc.csr -subj "/C=CN/ST=Liaoning/L=Dalian/O=Flomesh/OU=OSS-PQC/CN=www.example.com"
openssl x509 -req -in /opt/certs/pqc.csr -signkey /opt/certs/pqc.key -out /opt/certs/pqc.crt -days 365 -sha3-384

sudo tee /etc/systemd/system/nginx.service <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/opt/sbin/nginx -t
ExecStart=/opt/sbin/nginx
ExecReload=/opt/sbin/nginx -s reload
ExecStop=/opt/sbin/nginx -s stop
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo service nginx stop
sudo service nginx start
sudo service nginx status

openssl s_client -groups X25519MLKEM768 -connect localhost:443

加密算法分析

1. TLS 协议版本
协商版本：TLSv1.3
日志明确显示 Protocol: TLSv1.3，表明服务端强制使用 TLS 1.3 协议，该版本移除了不安全的旧算法（如 RC4、3DES），支持前向保密（Forward Secrecy）。
2. 密钥交换算法
协商曲线：X25519MLKEM768
日志中 Negotiated TLS1.3 group: X25519MLKEM768表明使用 X25519 椭圆曲线算法，密钥长度为 256 位。X25519 是 TLS 1.3 推荐的密钥交换算法，支持抗量子计算攻击，安全性高于传统 RSA 密钥交换。
3. 对称加密算法
加密套件：TLS_AES_256_GCM_SHA384
日志中 Cipher is TLS_AES_256_GCM_SHA384表示使用 AES-256-GCM 模式进行对称加密，结合 SHA-384 哈希算法。该组合提供高强度加密和数据完整性保护，是 TLS 1.3 的默认推荐配置。
4. 签名算法
签名类型：RSA-PSS-RSAE-SHA256
日志显示 Peer signature type: rsa_pss_rsae_sha256，表明服务端证书使用 RSA-PSS 签名算法（抗选择密文攻击）和 SHA-256 哈希函数


TLS 1.3 + MLKEM768（后量子密钥交换） + ML-DSA-44（后量子签名） + TLS_AES_256_GCM_SHA384（加密套件）

```

## 从源安装 CURL

```bash
apt remove curl -y --purge
wget --no-check-certificate https://github.com/curl/curl/releases/download/curl-8_16_0/curl-8.16.0.tar.gz
tar zxvf curl-8.16.0.tar.gz
cd curl-8.16.0
./configure --with-openssl=/usr/local/openssl

make
make install
sudo ldconfig
ln -s /usr/local/bin/curl /usr/bin/curl

#nginx
curl -k --tlsv1.3 https://127.0.0.1
curl -v -k --tlsv1.3 https://127.0.0.1 2>&1 | grep -E 'SSL connection|Certificate level'

#pqc-gateway
curl -k --resolve a.b.example.com:9443:127.0.0.1 -H "Host: 127.0.0.1:8080" --tlsv1.3 https://a.b.example.com:9443 -v
```

## 从源安装 WRK

```bash
git clone https://github.com/wg/wrk.git
cd wrk

make WITH_OPENSSL=/usr/local/openssl
cp wrk /usr/local/bin

wrk -t8 -c100 -d10s https://127.0.0.1

wrk -t8 -c1000 -d60s https://a.b.example.com:9443
Running 1m test @ https://a.b.example.com:9443
  8 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   110.35ms   33.88ms 768.37ms   74.04%
    Req/Sec     0.95k   334.04     2.95k    79.07%
  449846 requests in 1.00m, 102.96MB read
  Socket errors: connect 0, read 6766, write 0, timeout 0
Requests/sec:   7486.51
Transfer/sec:      1.71MB

wrk -t8 -c1000 -d60s https://a.b.example.com:443
Running 1m test @ https://a.b.example.com:443
  8 threads and 1000 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   105.28ms   28.58ms 768.95ms   99.27%
    Req/Sec   584.77    245.75     1.42k    80.51%
  275851 requests in 1.00m, 137.26MB read
  Socket errors: connect 730, read 61788, write 0, timeout 0
  Non-2xx or 3xx responses: 359
Requests/sec:   4591.02
Transfer/sec:      2.28MB
```

