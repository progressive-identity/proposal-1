.PHONY: all build process

DOCKER_IMAGE=alias/google
ALIAS_ROOT=/home/gawen/ressources/alias/root/gawen

all: build

build: alias_index.py
	docker build -t $(DOCKER_IMAGE) .

alias_index.py: ../../src/py/alias_index.py
	cp $< $@

process: alias_index.py
	docker run \
		--rm \
		-v `pwd`:/src \
		-v $(ALIAS_ROOT)/google:/alias/google/ \
		$(DOCKER_IMAGE)

