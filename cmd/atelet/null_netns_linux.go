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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/agent-substrate/substrate/internal/ateompath"
)

// nullNetNSPath is where runsc expects the pinned null gofer network
// namespace relative to its --shared-root (gVisor's
// specutils.NullNetNSFilename under ateompath.SharedRootDir).
var nullNetNSPath = filepath.Join(ateompath.SharedRootDir, "null-netns")

// validateSharedNullNetNS checks that nullNetNSPath satisfies runsc's
// openNullNetNS contract: an nsfs mount for a network namespace. Requires no
// privileges, so the unprivileged atelet container uses it to fail fast when
// the pin-null-netns initContainer's work is missing or broken.
func validateSharedNullNetNS() error {
	f, err := os.Open(nullNetNSPath)
	if err != nil {
		return err
	}
	defer f.Close()
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return fmt.Errorf("statfs %q: %w", nullNetNSPath, err)
	}
	if st.Type != unix.NSFS_MAGIC {
		return fmt.Errorf("%q is not a namespace mount", nullNetNSPath)
	}
	nsType, err := unix.IoctlRetInt(int(f.Fd()), unix.NS_GET_NSTYPE)
	if err != nil {
		return fmt.Errorf("getting namespace type of %q: %w", nullNetNSPath, err)
	}
	if nsType != unix.CLONE_NEWNET {
		return fmt.Errorf("%q is not a network namespace", nullNetNSPath)
	}
	return nil
}

// ensureSharedNullNetNS pins an empty ("null") network namespace at
// nullNetNSPath so every runsc gofer on this node reuses it instead of
// creating one per sandbox (runsc --shared-root). runsc only pins the
// namespace from inside the worker pod's mount namespace, where the bind
// mount is invisible to other workers; the pin-null-netns initContainer's
// run-ateom mount is Bidirectional, so a mount made here propagates to the
// host and from there into every worker's HostToContainer view.
//
// Needs CAP_SYS_ADMIN (unshare + mount); runs only in the privileged
// initContainer, once per atelet pod start.
func ensureSharedNullNetNS() error {
	if err := os.MkdirAll(ateompath.SharedRootDir, 0o755); err != nil {
		return fmt.Errorf("creating %q: %w", ateompath.SharedRootDir, err)
	}
	if err := validateSharedNullNetNS(); err == nil {
		slog.Info("Shared null gofer network namespace already pinned", slog.String("path", nullNetNSPath))
		return nil
	}
	f, err := os.OpenFile(nullNetNSPath, os.O_RDONLY|os.O_CREATE, 0o444)
	if err != nil {
		return fmt.Errorf("creating mount point %q: %w", nullNetNSPath, err)
	}
	f.Close()
	errCh := make(chan error, 1)
	go func() {
		// The unshared thread must never run other goroutines: stay locked
		// and let the thread be destroyed when the goroutine returns.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("unshare(CLONE_NEWNET): %w", err)
			return
		}
		if err := unix.Mount("/proc/thread-self/ns/net", nullNetNSPath, "", unix.MS_BIND, ""); err != nil {
			errCh <- fmt.Errorf("bind-mounting null netns at %q: %w", nullNetNSPath, err)
			return
		}
		errCh <- nil
	}()
	if err := <-errCh; err != nil {
		return err
	}
	if err := validateSharedNullNetNS(); err != nil {
		return fmt.Errorf("pinned namespace failed validation: %w", err)
	}
	slog.Info("Pinned shared null gofer network namespace", slog.String("path", nullNetNSPath))
	return nil
}
