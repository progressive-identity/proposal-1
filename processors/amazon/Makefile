.PHONY: all build process

DOCKER_IMAGE=alias/amazon
ALIAS_ROOT=/home/gawen/ressources/alias/root/mehdi

all: build

build: alias_index.py
	docker build -t $(DOCKER_IMAGE) .

alias_index.py: ../../src/py/alias_index.py
	cp $< $@

process:
	docker run \
		--rm \
		-v `pwd`:/src \
		-v $(ALIAS_ROOT)/amazon:/alias/amazon/ \
		$(DOCKER_IMAGE)

