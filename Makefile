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
GIT := git
EXTRA_TAGS += linuxbpf libbpfgo_full_static
else
$(error Cannot build BPF objects without clang installed.  Install clang or build with BUILD_LIBBPFGO=0.)
endif
endif

export EXTRA_TAGS

all:
	go run make.go -v autoDev

assets:
	go run make.go -v assets

auto:
	go run make.go -v auto

test:
	go test -race -v --tags server_vql ./...

test_light:
	go test -v --tags server_vql ./...

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

linux_m1:
	go run make.go -v LinuxM1

linux_musl:
	go run make.go -v LinuxMusl

always-check:

ifeq ($(BUILD_LIBBPFGO), 1)
BPF_MODULES := vql/linux/tcpsnoop/tcpsnoop.bpf.o \
	vql/linux/dnssnoop/dnssnoop.bpf.o \
	vql/linux/chattrsnoop/chattrsnoop.bpf.o

$(LIBBPFGO_DIR): always-check
	echo "INFO: updating submodule 'libbpfgo'"
	$(GIT) submodule update --init --recursive $@

$(LIBBPF_LIB): $(LIBBPFGO_DIR)
	make -C $(LIBBPFGO_DIR) libbpfgo-full-static

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
	go run make.go -v linux
linux_bare: $(BPF_MODULES)
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

debug:
	dlv debug --wd=. --build-flags="-tags 'server_vql extras'" ./bin/ -- frontend --disable-panic-guard -v --debug

debug_minion:
	dlv debug --wd=. --build-flags="-tags 'server_vql extras'" ./bin/ -- frontend --disable-panic-guard -v --debug --minion --node ${NODE}

debug_client:
	dlv debug --build-flags="-tags 'server_vql extras'" ./bin/ -- client -v

debug_golden:
	dlv debug --build-flags="-tags 'server_vql extras'" ./bin/ -- --config artifacts/testdata/windows/test.config.yaml golden artifacts/testdata/server/testcases/ --env srcDir=`pwd` --disable_alarm -v --filter=${GOLDEN}

lint:
	golangci-lint run

KapeFilesSync:
	python3 scripts/kape_files.py -t win ~/projects/KapeFiles/ > artifacts/definitions/Windows/KapeFiles/Targets.yaml
	python3 scripts/kape_files.py -t nix ~/projects/KapeFiles/ > artifacts/definitions/Linux/KapeFiles/CollectFromDirectory.yaml

SQLECmdSync:
	python3 scripts/sqlecmd_convert.py ~/projects/SQLECmd/ ~/projects/KapeFiles/ artifacts/definitions/Generic/Collectors/SQLECmd.yaml

# Do this after fetching the build artifacts with `gh run download <RunID>`
UpdateCIArtifacts:
	mv artifact/server/* artifacts/testdata/server/testcases/
	mv artifact/windows/* artifacts/testdata/windows/

UpdateCerts:
	cp /etc/ssl/certs/ca-certificates.crt crypto/ca-certificates.crt
	fileb0x crypto/b0x.yaml

# Use this to propare artifact packs at specific versions:
# First git checkout origin/v0.6.3
archive_artifacts:
	zip -r release_artifacts_$(basename "$(git status | head -1)").zip artifacts/definitions/ -i \*.yaml
