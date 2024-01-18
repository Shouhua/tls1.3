FROM nginx:latest

# RUN apt update
# RUN apt install -y openssl

# COPY ./content/* /usr/share/nginx/html/

# RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
#     -keyout /etc/ssl/private/nginx-selfsigned.key \
#     -out /etc/ssl/certs/nginx-selfsigned.crt \
#     -subj '/CN=US'

# COPY ./myCert.pem /etc/ssl/certs/
# COPY ./myPKey.pem /etc/ssl/private/

# COPY ./default.conf /etc/nginx/conf.d/default.conf

RUN echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm-updates main contrib non-free non-free-firmware" >> /etc/apt/sources.list && \
    echo "deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm-backports main contrib non-free non-free-firmware" >> /etc/apt/sources.list && \
    echo "deb https://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware" >> /etc/apt/sources.list && \
    mkdir -p /certs && \
    apt-get update && \
    apt-get install -y python3.11 python3-pip && \
    python3 -m pip install flask --break-system-packages

COPY ./app.py /
COPY ./start.sh /

CMD ["bash", "/start.sh"]