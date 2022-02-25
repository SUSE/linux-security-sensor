mkfile_dir := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
OUTPUT := $(mkfile_dir)output/.output
CLANG ?= clang-13
LLVM_STRIP ?= llvm-strip-13
LIBBPF_SRC := /root/bcc/src/cc/libbpf
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
INCLUDES := -I$(OUTPUT) -I$(LIBBPF_SRC)/include/uapi
CFLAGS := -g -O2 -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

GOFLAGS := CC=$(CLANG)
GOFLAGS += CGO_CFLAGS="-I$(abspath $(OUTPUT))"
GOFLAGS += CGO_LDFLAGS="-lelf -lz $(LIBBPF_OBJ) -lm"


all:
	go run make.go -v autoDev

auto:
	go run make.go -v auto

test:
	go test -race -v --tags server_vql ./...

golden:
	./output/velociraptor -v --config artifacts/testdata/windows/test.config.yaml golden artifacts/testdata/server/testcases/ --env srcDir=`pwd` --filter=${GOLDEN}

references:
	./output/velociraptor vql export docs/references/vql.yaml > docs/references/vql.yaml.tmp
	mv docs/references/vql.yaml.tmp docs/references/vql.yaml

release:
	go run make.go -v release

# Basic darwin binary - no yara.
darwin:
	go run make.go -v DarwinBase

darwin_intel:
	go run make.go -v Darwin

darwin_m1:
	go run make.go -v DarwinM1

linux: tcpsnoop.bpf.o
	$(GOFLAGS) go run make.go -v linux

$(OUTPUT) $(OUTPUT)/libbpf:
	@mkdir -p $@

%.bpf.o: $(mkfile_dir)vql/linux/tcpsnoop/%.bpf.c $(LIBBPF_OBJ) | $(OUTPUT)
	@$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH)	      \
		     -I./ $(INCLUDES) -c $(filter %.c,$^) -o $(mkfile_dir)vql/linux/tcpsnoop/$@ && \
	$(LLVM_STRIP) -g $(mkfile_dir)vql/linux/tcpsnoop/$@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/src/*.[ch]) | $(OUTPUT)/libbpf
	@$(MAKE) -C $(LIBBPF_SRC)/src BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=						  \
		    install

linux_bare:
	go run make.go -v linuxBare

freebsd:
	go run make.go -v freebsd

windows:
	go run make.go -v windowsDev

windows_bare:
	go run make.go -v windowsBare

windowsx86:
	go run make.go -v windowsx86

clean:
	go run make.go -v clean

generate:
	go generate ./vql/windows/
	go generate ./api/mock/

check:
	staticcheck ./...

build_docker:
	echo Building the initial docker container.
	docker build --tag velo_builder docker

build_release: build_docker
	echo Building release into output directory.
	docker run --rm -v `pwd`:/build/ -u `id -u`:`id -g` -e HOME=/tmp/  velo_builder

debug:
	dlv debug --wd=. --build-flags="-tags 'server_vql extras'" ./bin/ -- frontend --disable-panic-guard -v --debug

debug_client:
	dlv debug --build-flags="-tags 'server_vql extras'" ./bin/ -- client -v

debug_golden:
	dlv debug --build-flags="-tags 'server_vql extras'" ./bin/ -- --config artifacts/testdata/windows/test.config.yaml golden artifacts/testdata/server/testcases/ --env srcDir=`pwd` --disable_alarm --filter=${GOLDEN}

lint:
	golangci-lint run

KapeFilesSync:
	python3 scripts/kape_files.py -t win ~/projects/KapeFiles/ > artifacts/definitions/Windows/KapeFiles/Targets.yaml
	python3 scripts/kape_files.py -t nix ~/projects/KapeFiles/ > artifacts/definitions/Linux/KapeFiles/CollectFromDirectory.yaml

# Do this after fetching the build artifacts with `gh run download <RunID>`
UpdateCIArtifacts:
	mv artifact/server/* artifacts/testdata/server/testcases/
	mv artifact/windows/* artifacts/testdata/windows/

UpdateCerts:
	cp /etc/ssl/certs/ca-certificates.crt crypto/ca-certificates.crt
	fileb0x crypto/b0x.yaml
