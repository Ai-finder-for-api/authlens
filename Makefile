CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -fPIC -Icore/include
LIB      := authlens/libauthlens_core.so
TSC      ?= tsc

.PHONY: all core ui test test-core test-py clean run

all: core ui

core: $(LIB)

$(LIB): core/authlens_core.cpp core/include/authlens_core.h
	$(CXX) $(CXXFLAGS) -shared core/authlens_core.cpp -o $(LIB) -lcrypto

ui: ui/dist/main.js

ui/dist/main.js: $(wildcard ui/src/*.ts ui/src/views/*.ts)
	cd ui && $(TSC) -p tsconfig.json

test-core: core
	$(CXX) $(CXXFLAGS) core/tests/test_core.cpp -L authlens -lauthlens_core -o build_test_core \
		-Wl,-rpath,$(CURDIR)/authlens
	./build_test_core

test-py:
	python3 -m pytest -q tests

test: test-core test-py

run: core ui
	python3 -m authlens.cli serve --port 8770

clean:
	rm -rf ui/dist build_test_core $(LIB)
