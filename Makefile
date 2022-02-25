CLANG ?= clang
LLVM_STRIP ?= llvm-strip
CFLAGS := -g -O2 -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
EXTRA_TAGS =

GOOS := $(shell go env | grep GOOS|sed -e 's/^.*=//'|tr -d '"')
ifeq ($(GOOS),linux)
BUILD_LIBBPFGO ?= 1
endif

ifeq ($(BUILD_LIBBPFGO),1)
ifneq ($(shell command -pv $(CLANG);),)
LIBBPFGO_DIR := $(abspath third_party/libbpfgo)
LIBBPF_DIR := $(LIBBPFGO_DIR)/libbpf
LIBBPF_OUTPUT := $(LIBBPFGO_DIR)/output
LIBBPF_LIB := $(LIBBPF_OUTPUT)/libbpf.a
GOFLAGS += CGO_CFLAGS="-I$(LIBBPF_OUTPUT)"
GOFLAGS += CGO_LDFLAGS="$(LIBBPF_LIB)"
GIT := git
EXTRA_TAGS += linuxbpf
else
$(error Cannot build BPF objects without clang installed.  Install clang or build with BUILD_LIBBPFGO=0.)
endif
endif

export EXTRA_TAGS

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

always-check:

ifeq ($(BUILD_LIBBPFGO), 1)
BPF_MODULES := vql/linux/tcpsnoop/tcpsnoop.bpf.o

$(LIBBPFGO_DIR): always-check
	echo "INFO: updating submodule 'libbpfgo'"
	$(GIT) submodule update --init --recursive $@
	# Fake that it's an internal module
	rm -f $@/go.mod
	sed -e 's;"github.com/aquasecurity;"www.velocidex.com/golang/velociraptor/third_party;' -i $@/libbpfgo.go
	sed -e '/LDFLAGS/s/-lelf/-l:libelf.a/' -i $@/libbpfgo.go

$(LIBBPF_LIB): $(LIBBPFGO_DIR)
	make -C $(LIBBPFGO_DIR) libbpfgo-static

%.bpf.o: %.bpf.c $(LIBBPF_LIB)
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH)	      \
		     -I$(LIBBPF_OUTPUT) -I$(LIBBPF_DIR)/include/uapi \
		     -c $(filter %.c,$^) -o $@ && \
	$(LLVM_STRIP) -g $@
libbpfgo-clean:
	make -C $(LIBBPFGO_DIR) clean
LIBBPFGO_CLEAN := libbpfgo-clean
endif

linux: $(BPF_MODULES)
	$(GOFLAGS) go run make.go -v linux
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

go-clean:
	go run make.go -v clean

clean: go-clean $(LIBBPFGO_CLEAN)

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
