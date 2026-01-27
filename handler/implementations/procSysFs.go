//
// Copyright 2019-2023 Nestybox, Inc.
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
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

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
// * /proc/sys/fs/binfmt_misc (directory with status, register, and interpreter files)
//
// The binfmt_misc directory is fully emulated per container:
// - On first access, QEMU interpreters are cloned from the host
// - Changes inside the container do not affect the host
// - Each container has its own isolated binfmt_misc state
//

const (
	minProtectedSymlinksVal = 0
	maxProtectedSymlinksVal = 1
)

const (
	minProtectedHardlinksVal = 0
	maxProtectedHardlinksVal = 1
)

const (
	binfmtMiscPath         = "/proc/sys/fs/binfmt_misc"
	binfmtMiscStatusFile   = "status"
	binfmtMiscRegisterFile = "register"
	// Keys for storing binfmt_misc state in the container's data store.
	// The status key doubles as the initialization indicator (if status has data, we're initialized).
	binfmtMiscStatusKey = "/proc/sys/fs/binfmt_misc/status"
	// We need this key to track interpreter names since the data store has no prefix-query capability.
	binfmtMiscInterpretersKey = "sysbox-fs:binfmt_misc:interpreters"
)

type ProcSysFs struct {
	domain.HandlerBase
	// Mutex for binfmt_misc operations
	binfmtMiscMutex sync.Mutex
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
				Mode:    os.ModeDir | os.FileMode(uint32(0755)),
				Enabled: true,
			},
		},
	},
}

func (h *ProcSysFs) Lookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	var resource = n.Name()
	var nodePath = n.Path()

	logrus.Debugf("Executing Lookup() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// Handle binfmt_misc directory and its contents
	if strings.HasPrefix(nodePath, binfmtMiscPath) {
		return h.binfmtMiscLookup(n, req)
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

		if v.Kind == domain.DirEmuResource {
			info.FisDir = true
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
	var nodePath = n.Path()

	logrus.Debugf("Executing Open() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// Handle binfmt_misc directory and its contents
	if strings.HasPrefix(nodePath, binfmtMiscPath) {
		return false, nil
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
	var nodePath = n.Path()

	logrus.Debugf("Executing Read() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// Handle binfmt_misc directory contents
	if strings.HasPrefix(nodePath, binfmtMiscPath) {
		return h.binfmtMiscRead(n, req)
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
	var nodePath = n.Path()

	logrus.Debugf("Executing Write() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, resource)

	// Handle binfmt_misc directory contents
	if strings.HasPrefix(nodePath, binfmtMiscPath) {
		return h.binfmtMiscWrite(n, req)
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

	var nodePath = n.Path()

	logrus.Debugf("Executing ReadDirAll() for req-id: %#x, handler: %s, resource: %s",
		req.ID, h.Name, n.Name())

	// Handle binfmt_misc directory listing
	if nodePath == binfmtMiscPath {
		return h.binfmtMiscReadDirAll(n, req)
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

//
// binfmt_misc helper functions
//

// binfmtMiscInterpreter represents a binfmt_misc interpreter entry
type binfmtMiscInterpreter struct {
	Name        string
	Enabled     bool
	Interpreter string
	Flags       string
	Offset      string
	Magic       string
	Mask        string
	Extension   string
}

// binfmtMiscState holds the per-container binfmt_misc state
type binfmtMiscState struct {
	Enabled      bool
	Interpreters map[string]*binfmtMiscInterpreter
}

// initBinfmtMiscState initializes the binfmt_misc state for a container by
// cloning the host's QEMU interpreters. This is a one-time operation per container.
func (h *ProcSysFs) initBinfmtMiscState(req *domain.HandlerRequest) error {
	cntr := req.Container

	// Check if already initialized by checking if status has data
	statusData := make([]byte, 16)
	sz, _ := cntr.Data(binfmtMiscStatusKey, 0, &statusData)
	if sz > 0 {
		return nil
	}

	h.binfmtMiscMutex.Lock()
	defer h.binfmtMiscMutex.Unlock()

	// Double-check after acquiring lock
	sz, _ = cntr.Data(binfmtMiscStatusKey, 0, &statusData)
	if sz > 0 {
		return nil
	}

	logrus.Debugf("Initializing binfmt_misc state for container %s", cntr.ID())

	// Read and clone host interpreters
	hostDir, err := os.Open(binfmtMiscPath)
	if err != nil {
		// If host binfmt_misc is not available, just initialize with empty state
		logrus.Debugf("Host binfmt_misc not available: %v", err)
		if err := cntr.SetData(binfmtMiscInterpretersKey, 0, []byte("")); err != nil {
			return err
		}
		// Set status last (it's our initialization indicator)
		if err := cntr.SetData(binfmtMiscStatusKey, 0, []byte("enabled\n")); err != nil {
			return fmt.Errorf("failed to initialize binfmt_misc status: %v", err)
		}
		return nil
	}
	defer hostDir.Close()

	entries, err := hostDir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("failed to read host binfmt_misc directory: %v", err)
	}

	var interpreterNames []string
	for _, entry := range entries {
		// Skip status and register files
		if entry == binfmtMiscStatusFile || entry == binfmtMiscRegisterFile {
			continue
		}

		// Read the interpreter file from host
		hostInterpreterPath := filepath.Join(binfmtMiscPath, entry)
		content, err := os.ReadFile(hostInterpreterPath)
		if err != nil {
			logrus.Warnf("Failed to read host interpreter %s: %v", entry, err)
			continue
		}

		// Store in container's data store
		cntrInterpreterPath := filepath.Join(binfmtMiscPath, entry)
		if err := cntr.SetData(cntrInterpreterPath, 0, content); err != nil {
			logrus.Warnf("Failed to store interpreter %s: %v", entry, err)
			continue
		}

		interpreterNames = append(interpreterNames, entry)
		logrus.Debugf("Cloned host interpreter %s to container %s", entry, cntr.ID())
	}

	// Store the list of interpreter names
	if err := cntr.SetData(binfmtMiscInterpretersKey, 0, []byte(strings.Join(interpreterNames, "\n"))); err != nil {
		return err
	}

	// Set status last (it's our initialization indicator)
	if err := cntr.SetData(binfmtMiscStatusKey, 0, []byte("enabled\n")); err != nil {
		return fmt.Errorf("failed to initialize binfmt_misc status: %v", err)
	}

	return nil
}

// getBinfmtMiscInterpreters returns the list of interpreter names for the container
func (h *ProcSysFs) getBinfmtMiscInterpreters(req *domain.HandlerRequest) ([]string, error) {
	cntr := req.Container

	// Initialize if needed
	if err := h.initBinfmtMiscState(req); err != nil {
		return nil, err
	}

	data := make([]byte, 65536)
	sz, err := cntr.Data(binfmtMiscInterpretersKey, 0, &data)
	if err != nil && err != io.EOF {
		return nil, err
	}

	if sz == 0 {
		return []string{}, nil
	}

	interpreterList := strings.TrimSpace(string(data[:sz]))
	if interpreterList == "" {
		return []string{}, nil
	}

	return strings.Split(interpreterList, "\n"), nil
}

// binfmtMiscLookup handles Lookup for binfmt_misc paths
func (h *ProcSysFs) binfmtMiscLookup(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (os.FileInfo, error) {

	nodePath := n.Path()
	resource := n.Name()

	// Initialize if needed
	if err := h.initBinfmtMiscState(req); err != nil {
		return nil, fuse.IOerror{Code: syscall.EIO}
	}

	// Handle the binfmt_misc directory itself
	if nodePath == binfmtMiscPath {
		info := &domain.FileInfo{
			Fname:    "binfmt_misc",
			Fmode:    os.ModeDir | os.FileMode(uint32(0755)),
			FmodTime: time.Now(),
			FisDir:   true,
		}
		return info, nil
	}

	// Handle status file
	if resource == binfmtMiscStatusFile {
		info := &domain.FileInfo{
			Fname:    binfmtMiscStatusFile,
			Fmode:    os.FileMode(uint32(0644)),
			FmodTime: time.Now(),
			Fsize:    32,
		}
		return info, nil
	}

	// Handle register file (write-only)
	if resource == binfmtMiscRegisterFile {
		info := &domain.FileInfo{
			Fname:    binfmtMiscRegisterFile,
			Fmode:    os.FileMode(uint32(0200)),
			FmodTime: time.Now(),
			Fsize:    0,
		}
		return info, nil
	}

	// Handle interpreter files
	interpreters, err := h.getBinfmtMiscInterpreters(req)
	if err != nil {
		return nil, fuse.IOerror{Code: syscall.EIO}
	}

	for _, interp := range interpreters {
		if interp == resource {
			info := &domain.FileInfo{
				Fname:    resource,
				Fmode:    os.FileMode(uint32(0644)),
				FmodTime: time.Now(),
				Fsize:    4096,
			}
			return info, nil
		}
	}

	// Interpreter not found
	return nil, fuse.IOerror{Code: syscall.ENOENT}
}

// binfmtMiscRead handles Read for binfmt_misc files
func (h *ProcSysFs) binfmtMiscRead(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	nodePath := n.Path()
	resource := n.Name()
	cntr := req.Container

	// Initialize if needed
	if err := h.initBinfmtMiscState(req); err != nil {
		return 0, fuse.IOerror{Code: syscall.EIO}
	}

	cntr.Lock()
	defer cntr.Unlock()

	// Handle status file
	if resource == binfmtMiscStatusFile {
		data := make([]byte, 32)
		sz, err := cntr.Data(binfmtMiscStatusKey, req.Offset, &data)
		if err != nil && err != io.EOF {
			return 0, fuse.IOerror{Code: syscall.EIO}
		}
		if sz > len(req.Data) {
			sz = len(req.Data)
		}
		copy(req.Data, data[:sz])
		return sz, nil
	}

	// Handle register file (write-only, return empty)
	if resource == binfmtMiscRegisterFile {
		return 0, nil
	}

	// Handle interpreter files
	data := make([]byte, 4096)
	sz, err := cntr.Data(nodePath, req.Offset, &data)
	if err != nil && err != io.EOF {
		return 0, fuse.IOerror{Code: syscall.ENOENT}
	}
	if sz > len(req.Data) {
		sz = len(req.Data)
	}
	copy(req.Data, data[:sz])
	return sz, nil
}

// binfmtMiscWrite handles Write for binfmt_misc files
func (h *ProcSysFs) binfmtMiscWrite(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	nodePath := n.Path()
	resource := n.Name()
	cntr := req.Container

	// Initialize if needed
	if err := h.initBinfmtMiscState(req); err != nil {
		return 0, fuse.IOerror{Code: syscall.EIO}
	}

	cntr.Lock()
	defer cntr.Unlock()

	// Handle status file (enable/disable)
	if resource == binfmtMiscStatusFile {
		value := strings.TrimSpace(string(req.Data))
		switch value {
		case "0":
			if err := cntr.SetData(binfmtMiscStatusKey, 0, []byte("disabled\n")); err != nil {
				return 0, fuse.IOerror{Code: syscall.EIO}
			}
		case "1":
			if err := cntr.SetData(binfmtMiscStatusKey, 0, []byte("enabled\n")); err != nil {
				return 0, fuse.IOerror{Code: syscall.EIO}
			}
		case "-1":
			// Clear all interpreters - just reset the list
			// (the individual interpreter data remains in dataStore but won't be accessible)
			if err := cntr.SetData(binfmtMiscInterpretersKey, 0, []byte("")); err != nil {
				return 0, fuse.IOerror{Code: syscall.EIO}
			}
			if err := cntr.SetData(binfmtMiscStatusKey, 0, []byte("enabled\n")); err != nil {
				return 0, fuse.IOerror{Code: syscall.EIO}
			}
		default:
			return 0, fuse.IOerror{Code: syscall.EINVAL}
		}
		return len(req.Data), nil
	}

	// Handle register file (register new interpreter)
	if resource == binfmtMiscRegisterFile {
		return h.binfmtMiscRegister(req, cntr)
	}

	// Handle interpreter files (enable/disable/remove)
	interpreters, _ := h.getBinfmtMiscInterpretersLocked(cntr)
	found := false
	for _, interp := range interpreters {
		if interp == resource {
			found = true
			break
		}
	}
	if !found {
		return 0, fuse.IOerror{Code: syscall.ENOENT}
	}

	value := strings.TrimSpace(string(req.Data))
	switch value {
	case "0":
		// Disable interpreter
		return h.binfmtMiscSetInterpreterEnabled(cntr, nodePath, resource, false)
	case "1":
		// Enable interpreter
		return h.binfmtMiscSetInterpreterEnabled(cntr, nodePath, resource, true)
	case "-1":
		// Remove interpreter
		return h.binfmtMiscRemoveInterpreter(cntr, resource)
	default:
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}
}

// getBinfmtMiscInterpretersLocked returns the list of interpreter names (caller must hold lock)
func (h *ProcSysFs) getBinfmtMiscInterpretersLocked(cntr domain.ContainerIface) ([]string, error) {
	data := make([]byte, 65536)
	sz, err := cntr.Data(binfmtMiscInterpretersKey, 0, &data)
	if err != nil && err != io.EOF {
		return nil, err
	}

	if sz == 0 {
		return []string{}, nil
	}

	interpreterList := strings.TrimSpace(string(data[:sz]))
	if interpreterList == "" {
		return []string{}, nil
	}

	return strings.Split(interpreterList, "\n"), nil
}

// binfmtMiscRegister handles registering a new interpreter
func (h *ProcSysFs) binfmtMiscRegister(
	req *domain.HandlerRequest,
	cntr domain.ContainerIface) (int, error) {

	// Parse the registration string
	// Format: :name:type:offset:magic:mask:interpreter:flags
	regStr := strings.TrimSpace(string(req.Data))
	if !strings.HasPrefix(regStr, ":") {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	parts := strings.Split(regStr, ":")
	if len(parts) < 8 {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	name := parts[1]
	regType := parts[2]
	offset := parts[3]
	magic := parts[4]
	mask := parts[5]
	interpreter := parts[6]
	flags := ""
	if len(parts) > 7 {
		flags = parts[7]
	}

	if name == "" || interpreter == "" {
		return 0, fuse.IOerror{Code: syscall.EINVAL}
	}

	// Check if interpreter already exists
	interpreters, _ := h.getBinfmtMiscInterpretersLocked(cntr)
	for _, interp := range interpreters {
		if interp == name {
			return 0, fuse.IOerror{Code: syscall.EEXIST}
		}
	}

	// Build the interpreter file content
	var content strings.Builder
	content.WriteString("enabled\n")
	content.WriteString(fmt.Sprintf("interpreter %s\n", interpreter))
	if flags != "" {
		content.WriteString(fmt.Sprintf("flags: %s\n", flags))
	}
	if offset != "" {
		content.WriteString(fmt.Sprintf("offset %s\n", offset))
	}

	if regType == "M" {
		// Magic type
		content.WriteString(fmt.Sprintf("magic %s\n", magic))
		if mask != "" {
			content.WriteString(fmt.Sprintf("mask %s\n", mask))
		}
	} else if regType == "E" {
		// Extension type
		content.WriteString(fmt.Sprintf("extension .%s\n", magic))
	}

	// Store the interpreter
	interpPath := filepath.Join(binfmtMiscPath, name)
	if err := cntr.SetData(interpPath, 0, []byte(content.String())); err != nil {
		return 0, fuse.IOerror{Code: syscall.EIO}
	}

	// Update interpreter list
	interpreters = append(interpreters, name)
	if err := cntr.SetData(binfmtMiscInterpretersKey, 0, []byte(strings.Join(interpreters, "\n"))); err != nil {
		return 0, fuse.IOerror{Code: syscall.EIO}
	}

	logrus.Debugf("Registered new binfmt_misc interpreter: %s", name)

	return len(req.Data), nil
}

// binfmtMiscSetInterpreterEnabled enables or disables an interpreter
func (h *ProcSysFs) binfmtMiscSetInterpreterEnabled(
	cntr domain.ContainerIface,
	path string,
	name string,
	enabled bool) (int, error) {

	// Read current content
	data := make([]byte, 4096)
	sz, err := cntr.Data(path, 0, &data)
	if err != nil && err != io.EOF {
		return 0, fuse.IOerror{Code: syscall.EIO}
	}

	content := string(data[:sz])
	var newContent strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))
	firstLine := true

	for scanner.Scan() {
		line := scanner.Text()
		if firstLine {
			if enabled {
				newContent.WriteString("enabled\n")
			} else {
				newContent.WriteString("disabled\n")
			}
			firstLine = false
		} else {
			newContent.WriteString(line + "\n")
		}
	}

	if err := cntr.SetData(path, 0, []byte(newContent.String())); err != nil {
		return 0, fuse.IOerror{Code: syscall.EIO}
	}

	return 1, nil
}

// binfmtMiscRemoveInterpreter removes an interpreter
func (h *ProcSysFs) binfmtMiscRemoveInterpreter(
	cntr domain.ContainerIface,
	name string) (int, error) {

	// Update interpreter list to remove this one
	interpreters, _ := h.getBinfmtMiscInterpretersLocked(cntr)
	var newInterpreters []string
	for _, interp := range interpreters {
		if interp != name {
			newInterpreters = append(newInterpreters, interp)
		}
	}

	if err := cntr.SetData(binfmtMiscInterpretersKey, 0, []byte(strings.Join(newInterpreters, "\n"))); err != nil {
		return 0, fuse.IOerror{Code: syscall.EIO}
	}

	logrus.Debugf("Removed binfmt_misc interpreter: %s", name)

	return 2, nil
}

// binfmtMiscReadDirAll handles ReadDirAll for binfmt_misc directory
func (h *ProcSysFs) binfmtMiscReadDirAll(
	n domain.IOnodeIface,
	req *domain.HandlerRequest) ([]os.FileInfo, error) {

	// Initialize if needed
	if err := h.initBinfmtMiscState(req); err != nil {
		return nil, fuse.IOerror{Code: syscall.EIO}
	}

	var entries []os.FileInfo

	// Add status file
	entries = append(entries, &domain.FileInfo{
		Fname:    binfmtMiscStatusFile,
		Fmode:    os.FileMode(uint32(0644)),
		FmodTime: time.Now(),
		Fsize:    32,
	})

	// Add register file
	entries = append(entries, &domain.FileInfo{
		Fname:    binfmtMiscRegisterFile,
		Fmode:    os.FileMode(uint32(0200)),
		FmodTime: time.Now(),
		Fsize:    0,
	})

	// Add interpreter files
	interpreters, err := h.getBinfmtMiscInterpreters(req)
	if err != nil {
		return nil, fuse.IOerror{Code: syscall.EIO}
	}

	for _, interp := range interpreters {
		entries = append(entries, &domain.FileInfo{
			Fname:    interp,
			Fmode:    os.FileMode(uint32(0644)),
			FmodTime: time.Now(),
			Fsize:    4096,
		})
	}

	return entries, nil
}
