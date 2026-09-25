# harley — сборка статического бинарника для Alpine (musl не нужен: CGO_ENABLED=0).

BINARY  := harley
PKG     := ./cmd/harley
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GO      ?= go
DIST    := dist
ARCHES  := amd64 arm64

export CGO_ENABLED := 0

.PHONY: all build test test-xray vet release install xray clean

all: build

## build: статический бинарник для текущей платформы
build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) $(PKG)

## test: юнит-тесты (тесты с настоящим xray пропускаются, если его нет)
test:
	$(GO) test ./...

## test-xray: все тесты, включая проверку конфигов настоящим xray (XRAY_BIN=/path/to/xray)
test-xray:
	XRAY_BIN=$${XRAY_BIN:-$$(command -v xray)} $(GO) test -count=1 ./...

vet:
	$(GO) vet ./...

## release: dist/harley-linux-{amd64,arm64} + контрольные суммы
release: clean
	mkdir -p $(DIST)
	for arch in $(ARCHES); do \
		GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' \
			-o $(DIST)/$(BINARY)-linux-$$arch $(PKG) || exit 1; \
	done
	cp scripts/install.sh $(DIST)/
	mkdir -p $(DIST)/openrc && cp scripts/openrc/* $(DIST)/openrc/
	cd $(DIST) && sha256sum $(BINARY)-linux-* > SHA256SUMS

## install: установка в систему (нужен root)
install: build
	sh scripts/install.sh ./$(BINARY)

## xray: собрать xray-core из исходников (если GitHub-релизы недоступны, а Go-прокси есть)
XRAY_VERSION ?= latest
xray:
	GOBIN=$(CURDIR)/.xray-build $(GO) install -trimpath -ldflags '-s -w' github.com/xtls/xray-core/main@$(XRAY_VERSION)
	mv .xray-build/main ./xray && rmdir .xray-build
	@echo "готово: ./xray — установи: install -m 0755 xray /usr/local/bin/xray"

clean:
	rm -rf $(DIST) $(BINARY) xray .xray-build
