//
// Copyright 2019-2024 Nestybox, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package implementations

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
)

//
// /proc/sys/fs handler
//
// Emulated resources:
//
// * /proc/sys/fs/file-max
// * /proc/sys/fs/nr_open
// * /proc/sys/fs/protected_hardlinks
// * /proc/sys/fs/protected_symlinks
// * /proc/sys/fs/binfmt_misc (directory with per-container binfmt_misc support)
//
// binfmt_misc support:
// This handler provides per-container binfmt_misc support by:
// 1. Mounting binfmt_misc inside the container's mount namespace (on first access)
// 2. Cloning the host's binfmt_misc entries into the container
// 3. Passing through all operations to the real binfmt_misc filesystem
//
// This allows containers to:
// - Use all QEMU interpreters registered on the host
// - Register additional interpreters inside the container
// - Have full isolation (changes don't affect host or other containers)
//
// Requires kernel 6.7+ for binfmt_misc user-namespace support.
//

const (
	minProtectedSymlinksVal = 0
	maxProtectedSymlinksVal = 1
)

const (
	minProtectedHardlinksVal = 0
	maxProtectedHardlinksVal = 1
)

type ProcSysFs struct {
	domain.HandlerBase
	// Tracks which containers have binfmt_misc initialized
	binfmtInitializedContainers map[string]bool
	binfmtInitLock              sync.RWMutex
}

var ProcSysFs_Handler = &ProcSysFs{
	HandlerBase: domain.HandlerBase{
		Name:    "ProcSysFs",
		Path:    "/proc/sys/fs",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			"file-max": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    1024,
			},
			"nr_open": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0644)),
				Enabled: true,
				Size:    1024,
			},
			"protected_hardlinks": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0600)),
				Enabled: true,
				Size:    1024,
			},
			"protected_symlinks": {
				Kind:    domain.FileEmuResource,
				Mode:    os.FileMode(uint32(0600)),
				Enabled: true,
				Size:    1024,
			},
			"binfmt_misc": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0555)),
				Enabled: true,
			},
		},
	},
	binfmtInitializedContainers: make(map[string]bool),
	binfmtInitLock:              sync.RWMutex{},
}

// ensureBinfmtMiscInitialized ensures binfmt_misc is mounted inside the container
// and clones host entries if this is the first access.
func (h *ProcSysFs) ensureBinfmtMiscInitialized(req *domain.HandlerRequest) error {
	cntr := req.Container

	h.binfmtInitLock.RLock()
	initialized := h.binfmtInitializedContainers[cntr.ID()]
	h.binfmtInitLock.RUnlock()

	if initialized {
		return nil
	}

	h.binfmtInitLock.Lock()
	defer h.binfmtInitLock.Unlock()

	// Double-check after acquiring write lock
	if h.binfmtInitializedContainers[cntr.ID()] {
		return nil
	}

	// Mount binfmt_misc inside the container and clone host entries
	err := h.mountAndCloneBinfmtMisc(req)
	if err != nil {
		return err
	}

	h.binfmtInitializedContainers[cntr.ID()] = true

	logrus.Debugf("Initialized binfmt_misc for container %s", cntr.ID())

	return nil
}

// mountAndCloneBinfmtMisc mounts binfmt_misc in the container and clones host entries
func (h *ProcSysFs) mountAndCloneBinfmtMisc(req *domain.HandlerRequest) error {
	nss := h.Service.NSenterService()

	// First, mount binfmt_misc inside the container using nsenter
	// We need to enter all namespaces except mount-ns initially, then unshare mount-ns
	// to avoid affecting the container's visible mounts
	mountEvent := nss.NewEvent(
		req.Pid,
		&domain.AllNSs,
		unix.CLONE_NEWNS,
		&domain.NSenterMessage{
			Type: domain.MountSyscallRequest,
			Payload: []domain.MountSyscallPayload{
				{
					Mount: domain.Mount{
						Source: "binfmt_misc",
						Target: "/proc/sys/fs/binfmt_misc",
						FsType: "binfmt_misc",
						Flags:  0,
						Data:   "",
					},
				},
			},
		},
		nil,
		false,
	)

	err := nss.SendRequestEvent(mountEvent)
	if err != nil {
		logrus.Debugf("binfmt_misc mount request failed: %v", err)
		// Continue anyway - mount might already exist
	} else {
		responseMsg := nss.ReceiveResponseEvent(mountEvent)
		if responseMsg.Type == domain.ErrorResponse {
			logrus.Debugf("binfmt_misc mount response: %v (may already be mounted)", responseMsg.Payload)
			// Continue anyway - mount might already exist
		}
	}

	// Now clone host's binfmt_misc entries into the container
	err = h.cloneBinfmtHostEntries(req)
	if err != nil {
		logrus.Warnf("Failed to clone host binfmt_misc entries: %v", err)
		// Continue anyway - container may still work with existing entries
	}

	return nil
}

// cloneBinfmtHostEntries reads host's binfmt_misc entries and registers them in the container
func (h *ProcSysFs) cloneBinfmtHostEntries(req *domain.HandlerRequest) error {
	hostPath := "/proc/sys/fs/binfmt_misc"

	entries, err := os.ReadDir(hostPath)
	if err != nil {
		return fmt.Errorf("could not read host binfmt_misc: %w", err)
	}

	nss := h.Service.NSenterService()

	for _, entry := range entries {
		name := entry.Name()
		// Skip special files
		if name == "register" || name == "status" {
			continue
		}

		entryPath := filepath.Join(hostPath, name)
		data, err := os.ReadFile(entryPath)
		if err != nil {
			logrus.Debugf("Could not read binfmt entry %s: %v", name, err)
			continue
		}

		// Parse the entry and convert to register format
		registerStr := h.binfmtEntryToRegisterFormat(name, string(data))
		if registerStr == "" {
			logrus.Debugf("Could not convert binfmt entry %s to register format", name)
			continue
		}

		// Write to the container's register file using nsenter
		writeEvent := nss.NewEvent(
			req.Pid,
			&domain.AllNSs,
			unix.CLONE_NEWNS,
			&domain.NSenterMessage{
				Type: domain.WriteFileRequest,
				Payload: &domain.WriteFilePayload{
					File:        "/proc/sys/fs/binfmt_misc/register",
					Offset:      0,
					Data:        []byte(registerStr),
					MountSysfs:  false,
					MountProcfs: true,
				},
			},
			nil,
			false,
		)

		err = nss.SendRequestEvent(writeEvent)
		if err != nil {
			logrus.Debugf("Failed to send register request for %s: %v", name, err)
			continue
		}

		responseMsg := nss.ReceiveResponseEvent(writeEvent)
		if responseMsg.Type == domain.ErrorResponse {
			logrus.Debugf("Failed to register %s in container: %v", name, responseMsg.Payload)
			continue
		}

		logrus.Debugf("Cloned binfmt entry %s to container", name)
	}

	return nil
}

// binfmtEntryToRegisterFormat converts a binfmt_misc entry file content to the register format
// Register format: :name:type:offset:magic:mask:interpreter:flags
func (h *ProcSysFs) binfmtEntryToRegisterFormat(name, content string) string {
	var (
		interpreter string
		flags       string
		offset      string = "0"
		magic       string
		mask        string
		entryType   string = "M" // default to magic
	)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "interpreter ") {
			interpreter = strings.TrimPrefix(line, "interpreter ")
		} else if strings.HasPrefix(line, "flags: ") {
			flags = strings.TrimPrefix(line, "flags: ")
		} else if strings.HasPrefix(line, "offset ") {
			offset = strings.TrimPrefix(line, "offset ")
		} else if strings.HasPrefix(line, "magic ") {
			magic = strings.TrimPrefix(line, "magic ")
		} else if strings.HasPrefix(line, "mask ") {
			mask = strings.TrimPrefix(line, "mask ")
		} else if strings.HasPrefix(line, "extension ") {
			entryType = "E"
			magic = strings.TrimPrefix(line, "extension ")
		}
	}

	if interpreter == "" {
		return ""
	}

	// Format: :name:type:offset:magic:mask:interpreter:flags
	return fmt.Sprintf(":%s:%s:%s:%s:%s:%s:%s", name, entryType, offset, magic, mask, interpreter, flags)
}

// CleanupBinfmtContainer removes the tracking state for a container when it's unregistered.
func (h *ProcSysFs) CleanupBinfmtContainer(containerID string) {
	h.binfmtInitLock.Lock()
	defer h.binfmtInitLock.Unlock()

	delete(h.binfmtInitializedContainers, containerID)
	logrus.Debugf("Cleaned up binfmt_misc tracking for container %s", containerID)
}

// isBinfmtMiscResource checks if the given resource path is under binfmt_misc
func (h *ProcSysFs) isBinfmtMiscResource(n domain.IOnodeIface) bool {
	// Check parent path - only return true for resources INSIDE binfmt_misc
	// (not for binfmt_misc directory itself when accessed from /proc/sys/fs)
	nodePath := n.Path()
	return strings.Contains(nodePath, "/proc/sys/fs/binfmt_misc/") ||
		(nodePath == "/proc/sys/fs/binfmt_misc" && n.Name() != "binfmt_misc")
}

// isBinfmtMiscDir checks if this is the binfmt_misc directory itself
func (h *ProcSysFs) isBinfmtMiscDir(n domain.IOnodeIface) bool {
	return n.Name() == "binfmt_misc" && n.Path() == "/proc/sys/fs/binfmt_misc"
}

func (h *ProcSysFs) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// For the binfmt_misc directory itself, return emulated info
	// This prevents hangs when listing /proc/sys/fs before binfmt_misc is mounted
	if h.isBinfmtMiscDir(n) {
		if v, ok := h.EmuResourceMap["binfmt_misc"]; ok {
			info := &domain.FileInfo{
				Fname:    resource,
				Fmode:    v.Mode,
				FmodTime: time.Now(),
				Fsize:    v.Size,
			}
			return info, nil
		}
	}

	// Handle resources inside binfmt_misc specially
	if h.isBinfmtMiscResource(n) {
		// Ensure binfmt_misc is mounted and initialized
		if err := h.ensureBinfmtMiscInitialized(req); err != nil {
			logrus.Debugf("Failed to ensure binfmt_misc initialized: %v", err)
		}
		// Pass through to the real binfmt_misc inside the container
		return h.Service.GetPassThroughHandler().Lookup(n, req)
	}

	// Return an artificial fileInfo if looked-up element matches any of the
	// emulated nodes.
	if v, ok := h.EmuResourceMap[resource]; ok {
		info := &domain.FileInfo{
			Fname:    resource,
			Fmode:    v.Mode,
			FmodTime: time.Now(),
			Fsize:    v.Size,
		}

		return info, nil
	}

	// If looked-up element hasn't been found by now, let's look into the actual
	// sys container rootfs.
	return h.Service.GetPassThroughHandler().Lookup(n, req)
}

func (h *ProcSysFs) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (bool, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// Handle binfmt_misc directory and its contents specially
	if h.isBinfmtMiscDir(n) || h.isBinfmtMiscResource(n) {
		// Ensure binfmt_misc is mounted and initialized
		if err := h.ensureBinfmtMiscInitialized(req); err != nil {
			logrus.Debugf("Failed to ensure binfmt_misc initialized: %v", err)
		}
		// Pass through to the real binfmt_misc inside the container
		return h.Service.GetPassThroughHandler().Open(n, req)
	}

	switch resource {
	case "file-max":
		return false, nil

	case "nr_open":
		return false, nil

	case "protected_hardlinks":
		return false, nil

	case "protected_symlinks":
		return false, nil
	}

	return h.Service.GetPassThroughHandler().Open(n, req)
}

func (h *ProcSysFs) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// Handle binfmt_misc directory and its contents specially
	if h.isBinfmtMiscDir(n) || h.isBinfmtMiscResource(n) {
		// Ensure binfmt_misc is mounted and initialized
		if err := h.ensureBinfmtMiscInitialized(req); err != nil {
			logrus.Debugf("Failed to ensure binfmt_misc initialized: %v", err)
		}
		// Pass through to the real binfmt_misc inside the container
		return h.Service.GetPassThroughHandler().Read(n, req)
	}

	switch resource {
	case "file-max":
		return readCntrData(h, n, req)

	case "nr_open":
		return readCntrData(h, n, req)

	case "protected_hardlinks":
		return readCntrData(h, n, req)

	case "protected_symlinks":
		return readCntrData(h, n, req)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *ProcSysFs) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	var resource = n.Name()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// Handle binfmt_misc directory and its contents specially.
	// This allows users to register new QEMU interpreters by writing to
	// /proc/sys/fs/binfmt_misc/register (e.g., echo ':name:type:...' > register)
	if h.isBinfmtMiscDir(n) || h.isBinfmtMiscResource(n) {
		// Ensure binfmt_misc is mounted and initialized
		if err := h.ensureBinfmtMiscInitialized(req); err != nil {
			logrus.Debugf("Failed to ensure binfmt_misc initialized: %v", err)
		}
		// Pass through to the real binfmt_misc inside the container
		return h.Service.GetPassThroughHandler().Write(n, req)
	}

	switch resource {
	case "file-max":
		return writeCntrData(h, n, req, writeMaxIntToFs)

	case "nr_open":
		return writeCntrData(h, n, req, writeMaxIntToFs)

	case "protected_hardlinks":
		if !checkIntRange(req.Data, minProtectedHardlinksVal, maxProtectedHardlinksVal) {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		return writeCntrData(h, n, req, nil)

	case "protected_symlinks":
		if !checkIntRange(req.Data, minProtectedSymlinksVal, maxProtectedSymlinksVal) {
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		return writeCntrData(h, n, req, nil)
	}

	// Refer to generic handler if no node match is found above.
	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *ProcSysFs) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Handle binfmt_misc directory and its contents specially
	if h.isBinfmtMiscDir(n) || h.isBinfmtMiscResource(n) {
		// Ensure binfmt_misc is mounted and initialized
		if err := h.ensureBinfmtMiscInitialized(req); err != nil {
			logrus.Debugf("Failed to ensure binfmt_misc initialized: %v", err)
		}
		// Pass through to the real binfmt_misc inside the container
		return h.Service.GetPassThroughHandler().ReadDirAll(n, req)
	}

	// Return all entries as seen within container's namespaces.
	return h.Service.GetPassThroughHandler().ReadDirAll(n, req)
}

func (h *ProcSysFs) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	logrus.Debugf("Executing ReadLink() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	return h.Service.GetPassThroughHandler().ReadLink(n, req)
}

func (h *ProcSysFs) GetName() string {
	return h.Name
}

func (h *ProcSysFs) GetPath() string {
	return h.Path
}

func (h *ProcSysFs) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysFs) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysFs) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSysFs) GetResourcesList() []string {

	var resources []string

	for resourceKey, resource := range h.EmuResourceMap {
		resource.Mutex.Lock()
		if !resource.Enabled {
			resource.Mutex.Unlock()
			continue
		}
		resource.Mutex.Unlock()

		resources = append(resources, filepath.Join(h.GetPath(), resourceKey))
	}

	return resources
}

func (h *ProcSysFs) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysFs) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}
