package auparse

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func getSignalName(signalNum syscall.Signal) string {
        return unix.SignalName(syscall.Signal(signalNum))
}
