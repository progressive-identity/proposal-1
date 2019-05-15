FROM alpine

RUN apk add && \
    apk add python3 xz

COPY requirements.txt /
RUN pip3 install -r /requirements.txt

WORKDIR /src
COPY run.py .

VOLUME ["/alias/amazon/"]

CMD python3 run.py
