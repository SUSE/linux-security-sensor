// +build linux,!linuxbpf

package linux

// On Linux systemd without bpf enabled, we'll get a build failure for this
// module if all the source files are excluded.
