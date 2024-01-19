FROM nginx:latest

# NOTICE: debian bookwork没有/etc/apt/sources.list，只有/etc/apt/sources.list.d/debian.sources
RUN bash -c 'sed -i "s#http://deb.debian.org#https://mirrors.ustc.edu.cn#g" /etc/apt/sources.list.d/debian.sources && \
    mkdir -p /certs && \
    apt-get update && \
    apt-get install -y python3.11 python3-pip && \
    python3 -m pip install -i https://pypi.douban.com/simple/ flask --break-system-packages'

COPY ./app.py /
COPY ./start.sh /

CMD ["bash", "/start.sh"]