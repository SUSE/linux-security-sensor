package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"www.velocidex.com/golang/velociraptor/json"
)

type BPFBuildEnv struct {
	baseDir   string
	cflags    []string
	bpftool   string
}

func (self *BPFBuildEnv) outputDir() string {
	return filepath.Join(self.baseDir, "output")
}

func (self *BPFBuildEnv) bpftoolNeeded() (bool, error) {
	path:= filepath.Join(self.outputDir(), "vmlinux.h")

	_, err := os.Stat(path)
	if err == nil {
		return false, nil
	} else if os.IsNotExist(err) {
		return true, nil
	}

	return true, err
}

func (self *BPFBuildEnv) PrepareModules(arch, goos string) (tags string, env map[string]string, err error) {
	build := os.Getenv("BUILD_BPF_PLUGINS")
	disabled := false
	required := false
	if build != "" {
		disabled = build == "0"
		required = build == "1"
	}

	err = nil

	// Silently skip
	if disabled {
		fmt.Println("INFO: Not building bpf modules")
		return
	}

	if (goos != "linux" || runtime.GOARCH != arch) {
		errmsg := "BPF support can only be built natively and on Linux"
		if required {
			err = errors.New(errmsg)
			return
		}

		fmt.Printf("INFO: %s\n", errmsg)
		return
	}

	switch arch {
	case "amd64", "arm64", "ppc64le", "s390x":
	default:
		// Succeed with warning
		errmsg := fmt.Sprintf("BPF support is not implemented on %s", runtime.GOARCH)
		if required {
			err = errors.New(errmsg)
			return
		}
		fmt.Printf("INFO: %s\n", errmsg)
		return
	}

	// Check external dependencies
	missing := []string{}

	if os.Getenv("CLANG") == "" {
		_, err = exec.LookPath("clang")
		if err != nil {
			missing = append(missing, "clang")
		}
	}

	if os.Getenv("STRIP") == "" {
		_, err = exec.LookPath("llvm-strip")
		if err != nil {
			missing = append(missing, "llvm-strip")
		}
	}

	// We only need bpftool if the user hasn't provided vmlinux.h
	needed, err := self.bpftoolNeeded()
	if err != nil {
		return
	}

	if needed && os.Getenv("BPFTOOL") == "" {
		_, err = exec.LookPath("bpftool")
		if err != nil {
			// Some systems install bpftool in /usr/sbin and it's probably not
			// in the unprivileged user's path
			self.bpftool, err = exec.LookPath("/usr/sbin/bpftool")
		}
		if err != nil {
			missing = append(missing, "bpftool")
		}
	}

	if len(missing) > 0 {
		for _, tool := range missing {
			fmt.Printf("INFO: Cannot build BPF objects without %s installed.\n", tool)
		}
		if required {
			fmt.Println("ERROR: Either install the missing tools or build without BUILD_BPF_PLUGINS=1")
			err = fmt.Errorf("Missing external tools: %s", strings.Join(missing, ", "))
			return
		} else {
			fmt.Println("INFO: To build BPF plugins, install the required tools")
		}
	}

	fmt.Println("INFO: Generating BPF modules (if needed)")
	env = self.env()
	fmt.Printf("BPF Build Environment: %v\n", json.MustMarshalString(env))
	err = sh.RunWith(env, mg.GoCmd(), "generate", "./vql/linux/bpf/...")

	tags = " linuxbpf libbpfgo_static "
	return
}

func (self *BPFBuildEnv) env() map[string]string {
	env := make(map[string]string)
	path, err := filepath.Abs(self.outputDir())
	if err != nil {
		path = "."
	}

	env["CGO_CFLAGS"] = fmt.Sprintf("-I%s", path)
	env["CGO_LDFLAGS"] = fmt.Sprintf("%s/libbpf.a -l:libelf.a -lz -lzstd", path)
	if self.bpftool != "" {
		env["BPFTOOL"] = self.bpftool
	}

	return env
}

func (self *BPFBuildEnv) Clean() {
	sh.Run("make", "-C", "vql/linux/bpf", "clean")
}

func NewBPFBuildEnv() *BPFBuildEnv {
	return &BPFBuildEnv{
		baseDir: filepath.Join("third_party", "libbpfgo"),
		cflags:  []string{"-g", "-O2", "-Wall"},
	}
}
