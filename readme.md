# 生成证书

## 生成私钥

- openssl genpkey -out client.key -algorithm RSA -pkeyopt rsa_keygen_bits:2
  048
- openssl genpkey -out server.key -algorithm RSA -pkeyopt rsa_keygen_bits:2
  048

## 查看私钥

openssl pkey -in server.key -text -noout

## 创建证书请求

- openssl req -new -config client.cnf -key client.key -out client.csr
- openssl req -new -config server.cnf -key server.key -out server.csr

## 创建ca目录

- mkdir root-ca
- cd root-ca
- mkdir certs db private
- chmod 700 private
- touch db/index
- openssl rand -hex 16  > db/serial
- echo 1001 > db/crlnumber

## 创建sub-ca目录

- mkdir sub-ca
- cd sub-ca
- mkdir certs db private
- chmod 700 private
- touch db/index
- openssl rand -hex 16  > db/serial
- echo 1001 > db/crlnumber

## 创建证书

- openssl req -new -config root-ca.conf -out root-ca.csr -keyout private/root-ca.key
- openssl ca -selfsign -config root-ca.conf -in root-ca.csr -out root-ca.crt -extensions ca_ext
- openssl req -new -config sub-ca.conf -out sub-ca.csr -keyout private/sub-ca.key
- openssl ca -config root-ca.conf -in ../sub-ca/sub-ca.csr -out ../sub-ca/sub-ca.crt -extensions sub_ca_ext

- openssl ca -config sub-ca.conf -in ../server/server.csr -out ../server/server.crt -extensions server_ext
- openssl ca -config sub-ca.conf -in ../client/client.csr -out ../client/client.crt -extensions client_ext
- cat ../root-ca/root-ca.crt ../sub-ca/sub-ca.crt > ca.crt

## 测试证书

- openssl s_server -key server.key -cert server.crt -CAfile ca.crt -Verify 1 -port 20001 -tls1_2
- openssl s_client -CAfile ca.crt -cert client.crt -key client.key -showcerts 127.0.0.1:20001

