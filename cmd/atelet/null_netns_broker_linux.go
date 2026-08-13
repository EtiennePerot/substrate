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
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/agent-substrate/substrate/internal/ateompath"
)

// nullNetNSBroker shares one empty gofer network namespace fd per node with
// ateom pods over NullNetNSBrokerSocket. atelet itself cannot create network
// namespaces (it runs with no capabilities); the first ateom to boot a
// sandbox creates one and donates it here, and atelet's held fd keeps the
// namespace alive for every later sandbox on the node.
//
// Protocol (one request per connection):
//   'G' -> reply 'F' + netns fd via SCM_RIGHTS, or 'N' if none held yet
//   'D' + fd via SCM_RIGHTS -> reply 'K'; broker keeps the first valid fd
type nullNetNSBroker struct {
	mu sync.Mutex
	ns *os.File
}

// validateNetNSFD checks that fd refers to a network namespace (nsfs +
// NS_GET_NSTYPE == CLONE_NEWNET). Requires no capabilities.
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

// startNullNetNSBroker listens on NullNetNSBrokerSocket and serves in the
// background. Failure to serve is non-fatal for atelet: ateoms fall back to
// creating a namespace per sandbox, which is only slower.
func startNullNetNSBroker() {
	if err := os.Remove(ateompath.NullNetNSBrokerSocket); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("Failed to remove stale null netns broker socket", slog.Any("error", err))
		return
	}
	addr, err := net.ResolveUnixAddr("unix", ateompath.NullNetNSBrokerSocket)
	if err != nil {
		slog.Warn("Failed to resolve null netns broker socket address", slog.Any("error", err))
		return
	}
	lis, err := net.ListenUnix("unix", addr)
	if err != nil {
		slog.Warn("Failed to listen for null netns broker", slog.Any("error", err))
		return
	}
	if err := os.Chmod(ateompath.NullNetNSBrokerSocket, 0o600); err != nil {
		slog.Warn("Failed to restrict null netns broker socket", slog.Any("error", err))
		lis.Close()
		return
	}
	b := &nullNetNSBroker{}
	slog.Info("Null netns broker serving", slog.String("socket", ateompath.NullNetNSBrokerSocket))
	go func() {
		for {
			conn, err := lis.AcceptUnix()
			if err != nil {
				slog.Warn("Null netns broker accept failed; broker stopped", slog.Any("error", err))
				return
			}
			go b.handle(conn)
		}
	}()
}

func (b *nullNetNSBroker) handle(c *net.UnixConn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil || n < 1 {
		return
	}
	switch buf[0] {
	case 'G':
		b.mu.Lock()
		ns := b.ns
		b.mu.Unlock()
		if ns == nil {
			_, _ = c.Write([]byte{'N'})
			return
		}
		if _, _, err := c.WriteMsgUnix([]byte{'F'}, unix.UnixRights(int(ns.Fd())), nil); err != nil {
			slog.Warn("Null netns broker: sending fd failed", slog.Any("error", err))
		}
	case 'D':
		f := fileFromRights(oob[:oobn])
		if f == nil {
			return
		}
		if err := validateNetNSFD(int(f.Fd())); err != nil {
			slog.Warn("Null netns broker: rejecting donated fd", slog.Any("error", err))
			f.Close()
			return
		}
		b.mu.Lock()
		if b.ns == nil {
			b.ns = f
			slog.Info("Null netns broker: accepted donated namespace")
		} else {
			f.Close() // Lost the donation race; keep the first.
		}
		b.mu.Unlock()
		_, _ = c.Write([]byte{'K'})
	}
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
				first = os.NewFile(uintptr(fd), "donated-null-netns")
			} else {
				unix.Close(fd)
			}
		}
	}
	return first
}
