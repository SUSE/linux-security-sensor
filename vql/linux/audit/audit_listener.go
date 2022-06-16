package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	gMinimumSocketBufSize         = 512 * 1024
)

type AuditListener struct {
	sockFd int
	timeout int
	sockBufSize int

	poll_chan chan int
	error_chan chan error
	wg sync.WaitGroup
	stopPolling context.CancelFunc
}

func NewAuditListener() *AuditListener {
	return &AuditListener{
		wg: sync.WaitGroup{},
		poll_chan: make(chan int),
		error_chan: make(chan error),
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

func setSocketBufSize(fd int, sockBufSize int) error {
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

	pollctx, cancel := context.WithCancel(ctx)

	self.wg.Add(1)
	go func(ctx context.Context) {
		defer self.wg.Done()
		defer syscall.Close(epollFd)
		defer close(self.error_chan)
		defer close(self.poll_chan)

		ready := make([]unix.EpollEvent, 2)
		for {
			select {
			case <-pollctx.Done():
				return
			default:
				count, err := unix.EpollWait(epollFd, ready, 5000)
				if err != nil {
					if errors.Is(err, unix.EINTR) {
						continue
					}
					self.error_chan <- err
					return
				}

				if count > 0 {
					self.poll_chan <- count
				}
			}
		}
	}(ctx)

	self.sockFd = sockFd
	self.sockBufSize = sockBufSize
	self.stopPolling = cancel
	return nil
}

func (self *AuditListener) Wait(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-self.poll_chan:
			if !ok {
				continue
			}
		case err, ok := <-self.error_chan:
			if !ok {
				continue
			}
			return err
		}
		return nil
	}
}

func (self *AuditListener) Receive(buf *auditBuf) error {
	if len(buf.data) < unix.NLMSG_HDRLEN {
		return unix.EINVAL
	}

	size, from, err := unix.Recvfrom(self.sockFd, buf.data, unix.MSG_DONTWAIT)
	if err != nil {
		// Increase the size of the socket buffer and try again
		if errors.Is(err, unix.ENOBUFS) {
			err = setSocketBufSize(self.sockFd, self.sockBufSize * 4)
			if err != nil {
				return err
			}
			self.sockBufSize *= 4
			return unix.EAGAIN
		}

		// There likely won't be any listeners left and the socket
		// was closed in shutdown
		if errors.Is(err, unix.EBADF) {
			return fmt.Errorf("listener socket closed: %w", err)
		}

		// EAGAIN or EWOULDBLOCK will be returned for non-blocking reads where
		// the read would normally have blocked.
		return fmt.Errorf("receive failed: %w", err)
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
	self.stopPolling()
	syscall.Close(self.sockFd)
	self.wg.Wait()

	return nil
}
