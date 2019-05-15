.PHONY: all docker static clean clean-db sandbox redirect-ports lint

FLAKE8_ARGS = --max-line-length 180 --ignore _

all: docker

clean:
	rm src/static/jquery-3.4.0.min.js src/static/libsodium.js

	docker rmi alias/ref-python
	docker rmi alias/tls-proxy

clean-db:
	rm -rf store-debug/*

docker: static
	docker build -t alias/ref-python -f docker/Dockerfile.python src
	docker build -t alias/tls-proxy -f docker/Dockerfile.tls-proxy src/tls-proxy

up:
	docker-compose up

sandbox:
	docker run \
		--rm -it \
		-v `pwd`/store-debug:/store \
		-v `pwd`/src/templates:/templates \
		-v `pwd`/src/static:/static \
		-v `pwd`/src/py:/app \
		alias/ref-python /bin/sh

static: \
	src/static/jquery-3.4.0.min.js \
	src/static/libsodium.js

src/static/jquery-3.4.0.min.js:
	wget -O $@ https://code.jquery.com/jquery-3.4.0.min.js

src/static/libsodium.js:
	wget -O $@ https://raw.githubusercontent.com/jedisct1/libsodium.js/master/dist/browsers/sodium.js

redirect-ports:
	ssh -N -v \
		-R 0.0.0.0:8101:127.0.1.1:80 \
		-R 0.0.0.0:8102:127.0.1.2:80 \
		-R 0.0.0.0:8103:127.0.1.3:443 \
		cocoon.s.gawen.me

lint:
	flake8 $(FLAKE8_ARGS) src/py

