//go:build linux

// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	"github.com/agent-substrate/substrate/internal/ateompath"
)

// acquireGoferNetNS returns an fd for the node-shared empty gofer network
// namespace: from atelet's broker when available, otherwise freshly created
// here (ateom has CAP_SYS_ADMIN) and donated to the broker for later
// sandboxes on the node. The fd is passed to runsc create/restore as
// --gofer-network-namespace=/proc/self/fd/<n>, which runsc opens in-process
// (specutils.ApplyNS), so gofers join it instead of paying netns creation
// per sandbox boot.
func acquireGoferNetNS() (*os.File, error) {
	if f, err := goferNetNSFromBroker(); err == nil {
		slog.Info("Acquired gofer netns from broker")
		return f, nil
	} else if !errors.Is(err, errBrokerEmpty) {
		slog.Info("Gofer netns broker unavailable; creating locally", slog.Any("error", err))
	}
	f, err := newEmptyNetNS()
	if err != nil {
		return nil, err
	}
	if err := donateGoferNetNS(f); err != nil {
		slog.Info("Gofer netns donation failed; namespace stays pod-local", slog.Any("error", err))
	} else {
		slog.Info("Created gofer netns locally and donated to broker")
	}
	return f, nil
}

var errBrokerEmpty = errors.New("broker holds no namespace yet")

func dialNetNSBroker() (*net.UnixConn, error) {
	c, err := net.DialTimeout("unix", ateompath.NullNetNSBrokerSocket, time.Second)
	if err != nil {
		return nil, err
	}
	uc := c.(*net.UnixConn)
	_ = uc.SetDeadline(time.Now().Add(2 * time.Second))
	return uc, nil
}

func goferNetNSFromBroker() (*os.File, error) {
	c, err := dialNetNSBroker()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.Write([]byte{'G'}); err != nil {
		return nil, err
	}
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil || n < 1 {
		return nil, fmt.Errorf("reading broker reply: %w", err)
	}
	if buf[0] != 'F' {
		return nil, errBrokerEmpty
	}
	f := fileFromRights(oob[:oobn])
	if f == nil {
		return nil, errors.New("broker reply carried no fd")
	}
	if err := validateNetNSFD(int(f.Fd())); err != nil {
		f.Close()
		return nil, fmt.Errorf("broker fd invalid: %w", err)
	}
	return f, nil
}

func donateGoferNetNS(f *os.File) error {
	c, err := dialNetNSBroker()
	if err != nil {
		return err
	}
	defer c.Close()
	if _, _, err := c.WriteMsgUnix([]byte{'D'}, unix.UnixRights(int(f.Fd())), nil); err != nil {
		return err
	}
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err != nil || buf[0] != 'K' {
		return fmt.Errorf("donation not acknowledged: %w", err)
	}
	return nil
}

// newEmptyNetNS creates an empty network namespace and returns an fd
// referencing it. The fd alone keeps the namespace alive; the creating
// thread is sacrificed (never unlocked) so no goroutine ever runs in it.
func newEmptyNetNS() (*os.File, error) {
	type result struct {
		f   *os.File
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ch <- result{nil, fmt.Errorf("unshare(CLONE_NEWNET): %w", err)}
			return
		}
		f, err := os.Open("/proc/thread-self/ns/net")
		ch <- result{f, err}
	}()
	r := <-ch
	return r.f, r.err
}

// validateNetNSFD checks that fd refers to a network namespace (nsfs +
// NS_GET_NSTYPE == CLONE_NEWNET).
func validateNetNSFD(fd int) error {
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		return fmt.Errorf("statfs: %w", err)
	}
	if st.Type != unix.NSFS_MAGIC {
		return errors.New("not a namespace fd")
	}
	nsType, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil {
		return fmt.Errorf("NS_GET_NSTYPE: %w", err)
	}
	if nsType != unix.CLONE_NEWNET {
		return errors.New("not a network namespace fd")
	}
	return nil
}

// fileFromRights extracts the first fd from SCM_RIGHTS control data, closing
// any extras.
func fileFromRights(oob []byte) *os.File {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var first *os.File
	for i := range msgs {
		fds, err := unix.ParseUnixRights(&msgs[i])
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if first == nil {
				first = os.NewFile(uintptr(fd), "shared-null-netns")
			} else {
				unix.Close(fd)
			}
		}
	}
	return first
}
