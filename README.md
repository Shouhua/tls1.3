# 新增内容
研究TLS1.3主要是为了学习QUIC协议，QUIC协议使用了修改的TLS1.3。
## 使用
server可以使用nginx或者本地的ssl库新建的server脚本
### 使用nginx作为server
```shell
# 需要将证书和私钥移动到test_server/nginx/certs
openssl req -x509 -noenc -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -subj "/C=CN/ST=Gufei/L=Xukan/O=MyOrg/OU=MyBG/CN=localhost/emailAddress=email@examle.com" -addext "subjectAltName=DNS:localhost"

# 进入test_server执行生成镜像
docker build -t nginxtls13 .

# 在根目录执行如下，主要是做了目录映射，便于修改，不用每次都build镜像
# 注意映射的端口和文件夹目录
docker run -itd --name tls -p 4433:443 \
	-v $(pwd)/test_server/nginx/content:/usr/share/nginx/html \
	-v $(pwd)/test_server/nginx/config:/etc/nginx/conf.d \
	-v $(pwd)/test_server/nginx/certs:/certs \
	nginxtls13
```
### 使用python ssl库新建的server，不支持early data
```shell
# 更改main.py中的ip，port，msg，msg更改是因为这个server不支持http协议
python server.py
```

### 运行client端
```shell
# 修改pip源
cat > ~/.pip/pip.conf <<-'EOF'
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
[install]
trusted-host = https://pypi.tuna.tsinghua.edu.cn
EOF

python3 -m venv .venv
python3 -m pip install cryptography pyopenssl certifi service-identity
python main.py
```
## Changelog
1. 续写O-RTT，发送early data，server验证成功，并且返回请求内容，主要代码在resume函数中，中间比较绕的是各种密钥的计算，另外要注意各种hash值的计算
5. add Certificate, CertificateVerify, Finished验证
4. 有个疑问，为什么有时候server在不等待end of early data就直接发送application data了？
2. 为了在wireshark中调试，输出keylogfile文件，输出代码见keylogfile
3. 调试。有多个server
- 使用openssl s_client来查看标准的流程
- 使用本地server，运行```python server.py```
- 使用test_server，需要build镜像
6. 调整test_server docker file
7. 测试 python3 -m unittest -v tests/test_crypto.py
8. 使用python官方的ssl库写的debug server，不支持early data
9. 使用vscode插件black-formatter, isort

# 以下为作者的README
# TLS 1.3
The goal of this project is to better understand TLS 1.3 by creating a pure python implementation. Let's see how this goes!


## Resources
Some resources that will be useful to us when learning about TLS 1.3
*  The Transport Layer Security (TLS) Protocol Version 1.3 [RFC 8446](https://tools.ietf.org/html/rfc8446)
    *  An Interface and Algorithms for Authenticated Encryption [RFC 5116](https://tools.ietf.org/html/rfc5116)
    *  HMAC-based Extract-and-Expand Key Derivation Function (HKDF) [RFC 5869](https://tools.ietf.org/html/rfc5869)
* [Test for TLS 1.3 Support](https://www.cdn77.com/tls-test)
* [TLS 1.3 illustrated](https://tls13.ulfheim.net/)

### Test Endpoint
We want a server that we can make TLS 1.3 requests to and also enable 0-RTT (because I couldn't find a server that supports this...)

### Helpful snippet
Client:

```bash
echo -e "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n" > request.txt
openssl s_client -connect 127.0.0.1:4433 -tls1_3 -sess_out session.pem -keylogfile ./keylogfile -ign_eof < request.txt
openssl s_client -connect 127.0.0.1:4433 -tls1_3 -sess_in session.pem -keylogfile ./keylogfile -early_data request.txt
```

Server:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout myPKey.pem \
    -out myCert.crt \
    -subj '/CN=US'
openssl s_server -accept portNum -cert myCert.pem -key myPKey.pem
```

### Testing Container
To test tls1.3 on our own endpoint (couldn't find one with 0-RTT enabled) we will use an instance made by us.

To build:
```bash
cd ./test_server
docker build . -t nginxtls13:latest
```
To run:
```bash
docker run -p4433:443 -it nginxtls13
```

### Crazy Debugging
When working on session resumption, there were some issues. To debug these issues I edited openssl (added some print statements) so that I could see what openssl was looking at and compare that to my code. This was some pretty hard debugging...

You can see the diffs to openssl in ```resources/openssl.diff```

The setup to make openssl compile is pretty simple. Just install it from git 
```bash
git clone <openssl>
cd openssl
# apply changes
make install
openssl s_server -accept portNum -cert myCert.pem -key myPKey.pem
```

## Goals
 - [x] Send an HTTP GET request to a TLS 1.3 server.
 - [x] Clean up code a bunch!!!
    - [ ] Get a decent code review
 - [ ] Session resumption (0-RTT)

