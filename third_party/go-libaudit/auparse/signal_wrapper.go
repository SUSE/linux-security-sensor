// +build !linux

package auparse

import (
	"syscall"
)

func getSignalName(signalNum syscall.Signal) string {
        return syscall.Signal(signalNum).String()
}
