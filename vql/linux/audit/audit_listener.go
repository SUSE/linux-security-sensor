package audit

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

var gMinimumSocketBufSize = 512 * 1024

type AuditListener struct {
	sockFd      int
	epollFd     int
	sockBufSize int
}

func NewAuditListener() *AuditListener {
	return &AuditListener{
		sockFd:  -1,
		epollFd: -1,
	}
}

func openAuditListenerSocket() (int, error) {
	sockFd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return -1, err
	}

	src := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: unix.AUDIT_NLGRP_READLOG,
	}

	err = syscall.Bind(sockFd, src)
	if err != nil {
		syscall.Close(sockFd)
		return -1, fmt.Errorf("Could not bind to netlink socket: %w", err)
	}

	return sockFd, nil
}

func setSocketBufSize(fd, sockBufSize int) error {
	err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, sockBufSize)
	if err != nil {
		err = fmt.Errorf("failed to increase listener socket buffer size (size %v): %w.  Events may be lost.", sockBufSize, err)
	}

	return err
}

func openEpollDescriptor(fd int) (int, error) {
	pollFd, err := unix.EpollCreate1(0)
	if err != nil {
		return -1, err
	}

	err = unix.EpollCtl(pollFd, unix.EPOLL_CTL_ADD, fd,
		&unix.EpollEvent{
			Events: unix.POLLIN | unix.POLLHUP,
			Fd:     int32(fd),
		})
	if err != nil {
		syscall.Close(pollFd)
		return -1, err
	}

	return pollFd, nil
}

func (self *AuditListener) Open(ctx context.Context) error {
	if self.sockFd >= 0 {
		return syscall.EBUSY
	}

	sockFd, err := openAuditListenerSocket()
	if err != nil {
		return fmt.Errorf("could not open listener socket: %w", err)
	}

	epollFd, err := openEpollDescriptor(sockFd)
	if err != nil {
		syscall.Close(sockFd)
		return fmt.Errorf("could not open epoll socket: %w", err)
	}

	sockBufSize, err := unix.GetsockoptInt(sockFd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		syscall.Close(sockFd)
		syscall.Close(epollFd)
		return fmt.Errorf("could not get socket receive buffer size: %w", err)
	}

	if sockBufSize < gMinimumSocketBufSize {
		sockBufSize = gMinimumSocketBufSize
		err = setSocketBufSize(sockFd, sockBufSize)
		if err != nil {
			syscall.Close(sockFd)
			syscall.Close(epollFd)
			return err
		}
	}

	self.sockFd = sockFd
	self.epollFd = epollFd
	self.sockBufSize = sockBufSize
	return nil
}

func (self *AuditListener) Wait(ctx context.Context) error {
	if self.sockFd < 0 {
		return syscall.ENOTCONN
	}

	ready := make([]unix.EpollEvent, 2)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		count, err := unix.EpollWait(self.epollFd, ready, 5000)
		if err != nil {
			if errors.Is(syscall.EINTR, err) {
				continue
			}
			return err
		}
		if count > 0 {
			return nil
		}
	}
}

func (self *AuditListener) Receive(buf *auditBuf) error {
	if self.sockFd < 0 {
		return syscall.ENOTCONN
	}
	if len(buf.data) < unix.NLMSG_HDRLEN {
		return unix.EINVAL
	}

	size, from, err := unix.Recvfrom(self.sockFd, buf.data, unix.MSG_DONTWAIT)
	if err != nil {
		// Increase the size of the socket buffer and try again
		if errors.Is(err, unix.ENOBUFS) {
			err = setSocketBufSize(self.sockFd, self.sockBufSize*4)
			if err != nil {
				return err
			}
			self.sockBufSize *= 4
			return errRetryNeeded
		}

		// EAGAIN or EWOULDBLOCK will be returned for non-blocking reads where
		// the read would normally have blocked.
		return err
	}

	if size < unix.NLMSG_HDRLEN {
		return fmt.Errorf("not enough bytes (%v) received to form a netlink header", size)
	}

	fromNetlink, ok := from.(*unix.SockaddrNetlink)
	if !ok || fromNetlink.Pid != 0 {
		// Spoofed packet received on audit netlink socket.
		return errors.New("message received was not from the kernel")
	}

	buf.size = size
	return nil
}

func (self *AuditListener) Close() error {
	if self.sockFd < 0 {
		return syscall.ENOTCONN
	}
	syscall.Close(self.epollFd)
	syscall.Close(self.sockFd)

	self.epollFd = -1
	self.sockFd = -1
	return nil
}
