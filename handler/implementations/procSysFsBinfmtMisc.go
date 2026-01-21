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

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/nestybox/sysbox-fs/domain"
)

//
// /proc/sys/fs/binfmt_misc handler
//
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

type ProcSysFsBinfmtMisc struct {
	domain.HandlerBase
	// Tracks which containers have been initialized
	initializedContainers map[string]bool
	initLock              sync.RWMutex
}

var ProcSysFsBinfmtMisc_Handler = &ProcSysFsBinfmtMisc{
	domain.HandlerBase{
		Name:    "ProcSysFsBinfmtMisc",
		Path:    "/proc/sys/fs/binfmt_misc",
		Enabled: true,
		EmuResourceMap: map[string]*domain.EmuResource{
			".": {
				Kind:    domain.DirEmuResource,
				Mode:    os.ModeDir | os.FileMode(uint32(0555)),
				Enabled: true,
			},
		},
	},
	make(map[string]bool),
	sync.RWMutex{},
}

// ensureBinfmtMiscInitialized ensures binfmt_misc is mounted inside the container
// and clones host entries if this is the first access.
func (h *ProcSysFsBinfmtMisc) ensureBinfmtMiscInitialized(req *domain.HandlerRequest) error {
	cntr := req.Container

	h.initLock.RLock()
	initialized := h.initializedContainers[cntr.ID()]
	h.initLock.RUnlock()

	if initialized {
		return nil
	}

	h.initLock.Lock()
	defer h.initLock.Unlock()

	// Double-check after acquiring write lock
	if h.initializedContainers[cntr.ID()] {
		return nil
	}

	// Mount binfmt_misc inside the container and clone host entries
	err := h.mountAndCloneBinfmtMisc(req)
	if err != nil {
		return err
	}

	h.initializedContainers[cntr.ID()] = true

	logrus.Debugf("Initialized binfmt_misc for container %s", cntr.ID())

	return nil
}

// mountAndCloneBinfmtMisc mounts binfmt_misc in the container and clones host entries
func (h *ProcSysFsBinfmtMisc) mountAndCloneBinfmtMisc(req *domain.HandlerRequest) error {
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
	err = h.cloneHostEntries(req)
	if err != nil {
		logrus.Warnf("Failed to clone host binfmt_misc entries: %v", err)
		// Continue anyway - container may still work with existing entries
	}

	return nil
}

// cloneHostEntries reads host's binfmt_misc entries and registers them in the container
func (h *ProcSysFsBinfmtMisc) cloneHostEntries(req *domain.HandlerRequest) error {
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
		registerStr := h.entryToRegisterFormat(name, string(data))
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

// entryToRegisterFormat converts a binfmt_misc entry file content to the register format
// Register format: :name:type:offset:magic:mask:interpreter:flags
func (h *ProcSysFsBinfmtMisc) entryToRegisterFormat(name, content string) string {
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

func (h *ProcSysFsBinfmtMisc) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Ensure binfmt_misc is mounted and initialized
	if err := h.ensureBinfmtMiscInitialized(req); err != nil {
		logrus.Debugf("Failed to ensure binfmt_misc initialized: %v", err)
	}

	// Pass through to the real binfmt_misc inside the container
	return h.Service.GetPassThroughHandler().Lookup(n, req)
}

func (h *ProcSysFsBinfmtMisc) Open(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (bool, error) {

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Ensure binfmt_misc is mounted and initialized
	if err := h.ensureBinfmtMiscInitialized(req); err != nil {
		logrus.Debugf("Failed to ensure binfmt_misc initialized: %v", err)
	}

	// Pass through to the real binfmt_misc inside the container
	return h.Service.GetPassThroughHandler().Open(n, req)
}

func (h *ProcSysFsBinfmtMisc) Read(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Ensure binfmt_misc is mounted and initialized
	if err := h.ensureBinfmtMiscInitialized(req); err != nil {
		logrus.Debugf("Failed to ensure binfmt_misc initialized: %v", err)
	}

	// Pass through to the real binfmt_misc inside the container
	return h.Service.GetPassThroughHandler().Read(n, req)
}

func (h *ProcSysFsBinfmtMisc) Write(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Ensure binfmt_misc is mounted and initialized
	if err := h.ensureBinfmtMiscInitialized(req); err != nil {
		logrus.Debugf("Failed to ensure binfmt_misc initialized: %v", err)
	}

	// Pass through to the real binfmt_misc inside the container
	return h.Service.GetPassThroughHandler().Write(n, req)
}

func (h *ProcSysFsBinfmtMisc) ReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Ensure binfmt_misc is mounted and initialized
	if err := h.ensureBinfmtMiscInitialized(req); err != nil {
		logrus.Debugf("Failed to ensure binfmt_misc initialized: %v", err)
	}

	// Pass through to the real binfmt_misc inside the container
	return h.Service.GetPassThroughHandler().ReadDirAll(n, req)
}

func (h *ProcSysFsBinfmtMisc) ReadLink(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (string, error) {

	logrus.Debugf("Executing ReadLink() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Pass through to the real binfmt_misc inside the container
	return h.Service.GetPassThroughHandler().ReadLink(n, req)
}

func (h *ProcSysFsBinfmtMisc) GetName() string {
	return h.Name
}

func (h *ProcSysFsBinfmtMisc) GetPath() string {
	return h.Path
}

func (h *ProcSysFsBinfmtMisc) GetService() domain.HandlerServiceIface {
	return h.Service
}

func (h *ProcSysFsBinfmtMisc) GetEnabled() bool {
	return h.Enabled
}

func (h *ProcSysFsBinfmtMisc) SetEnabled(b bool) {
	h.Enabled = b
}

func (h *ProcSysFsBinfmtMisc) GetResourcesList() []string {
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

func (h *ProcSysFsBinfmtMisc) GetResourceMutex(n domain.IOnodeIface) *sync.Mutex {
	resource, ok := h.EmuResourceMap[n.Name()]
	if !ok {
		return nil
	}

	return &resource.Mutex
}

func (h *ProcSysFsBinfmtMisc) SetService(hs domain.HandlerServiceIface) {
	h.Service = hs
}

// CleanupContainer removes the tracking state for a container when it's unregistered.
func (h *ProcSysFsBinfmtMisc) CleanupContainer(containerID string) {
	h.initLock.Lock()
	defer h.initLock.Unlock()

	delete(h.initializedContainers, containerID)
	logrus.Debugf("Cleaned up binfmt_misc tracking for container %s", containerID)
}
