.PHONY: all build process

DOCKER_IMAGE=alias/processor-google
ALIAS_ROOT=/home/gawen/src/gawen/alias/db/rsrc/gawen

all: build

build: index.py scope.py
	docker build -t $(DOCKER_IMAGE) .

index.py: ../../src/py/index.py
	cp $< $@

scope.py: ../../src/py/scope.py
	cp $< $@

process: alias_index.py
	docker run \
		--rm \
		-v `pwd`:/src \
		-v $(ALIAS_ROOT)/google:/alias/google/ \
		$(DOCKER_IMAGE)

