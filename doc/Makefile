.PHONY: all clean

MMDC=docker run --rm -v `pwd`:/mmd adoroszlai/mmdc

all: auth_code_grant.svg

auth_code_grant.svg: auth_code_grant.mmd
	$(MMDC) -i $< -o $@

clean:
	rm -f *.svg
