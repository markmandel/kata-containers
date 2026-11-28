// Copyright (c) 2026 Agones Authors
//
// SPDX-License-Identifier: Apache-2.0
//

// Experimental live-migration "receive mode" for a Cloud Hypervisor sandbox.
//
// A receive-mode sandbox is a placeholder pod: the shim prepares everything around the VM (netns,
// shared filesystem, virtiofsd, CH) but does not boot a guest. Once every expected container has
// been created (so each one's files are shared at the *source* pod's paths), it receives the
// running VM from the source over Cloud Hypervisor live migration, hot-plugs this pod's NIC, and
// re-uses the migrated agent, whose containers are already running. Container IDs are translated
// to the source IDs the agent knows.
//
// Driven by pod annotations (passed through by containerd's pod_annotations):
//   migrate.agones.dev/receive         receiver URL, e.g. tcp:0.0.0.0:6000
//   migrate.agones.dev/source-sandbox  the source pod's sandbox ID
//   migrate.agones.dev/containers      name=sourceContainerID,... for every app container

package virtcontainers

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
	"github.com/sirupsen/logrus"
)

const (
	annMigrateReceive       = "migrate.agones.dev/receive"
	annMigrateSourceSandbox = "migrate.agones.dev/source-sandbox"
	annMigrateContainers    = "migrate.agones.dev/containers"
	annCRIContainerName     = "io.kubernetes.cri.container-name"
)

type migrationReceive struct {
	url        string
	srcSandbox string
	dstSandbox string
	byName     map[string]string // app container name -> source container ID

	mu    sync.Mutex
	idMap map[string]string // destination container ID -> source container ID
	done  chan struct{}     // closed once the VM has been received
	once  sync.Once
	err   error
}

func migrationLogger() *logrus.Entry {
	return virtLog.WithField("subsystem", "migration")
}

// newMigrationReceive returns nil unless the sandbox annotations ask for receive mode.
func newMigrationReceive(annotations map[string]string, sandboxID string) (*migrationReceive, error) {
	url := annotations[annMigrateReceive]
	if url == "" {
		return nil, nil
	}
	m := &migrationReceive{
		url:        url,
		srcSandbox: annotations[annMigrateSourceSandbox],
		dstSandbox: sandboxID,
		byName:     map[string]string{},
		idMap:      map[string]string{sandboxID: annotations[annMigrateSourceSandbox]},
		done:       make(chan struct{}),
	}
	if m.srcSandbox == "" {
		return nil, fmt.Errorf("%s needs %s", annMigrateReceive, annMigrateSourceSandbox)
	}
	for _, pair := range strings.Split(annotations[annMigrateContainers], ",") {
		name, id, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || name == "" || id == "" {
			continue
		}
		m.byName[name] = id
	}
	if len(m.byName) == 0 {
		return nil, fmt.Errorf("%s needs %s", annMigrateReceive, annMigrateContainers)
	}
	migrationLogger().WithFields(logrus.Fields{"url": url, "source": m.srcSandbox, "containers": m.byName}).
		Info("sandbox is in migration receive mode")
	return m, nil
}

// sourceID returns the source container ID for a destination container, recording the mapping.
func (m *migrationReceive) sourceID(c *Container) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.idMap[c.id]; ok {
		return id
	}
	if id, ok := m.byName[c.config.Annotations[annCRIContainerName]]; ok {
		m.idMap[c.id] = id
		return id
	}
	return c.id
}

// allCreated reports whether every expected app container has been mapped.
func (m *migrationReceive) allCreated() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.idMap) == len(m.byName)+1 // +1: the sandbox container
}

func (m *migrationReceive) received() bool {
	select {
	case <-m.done:
		return true
	default:
		return false
	}
}

func (m *migrationReceive) finish(err error) {
	m.once.Do(func() {
		m.err = err
		close(m.done)
	})
}

// shareID is the ID used to name a container's files in the shared directory. In receive mode
// that's the source container's ID, so the migrated virtiofsd state finds the same paths.
func shareID(c *Container) string {
	if c.sandbox != nil && c.sandbox.migration != nil {
		return c.sandbox.migration.sourceID(c)
	}
	return c.id
}

// shareFileSuffix replaces the random part of shared file names with one derived from the mount
// destination, so source and destination shims produce the same names.
func shareFileSuffix(destination string) string {
	sum := sha256.Sum256([]byte(destination))
	return hex.EncodeToString(sum[:8])
}

// translate rewrites ContainerId/ExecId fields of an agent request to the source IDs.
func (m *migrationReceive) translate(request interface{}) {
	v := reflect.ValueOf(request)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, name := range []string{"ContainerId", "ExecId"} {
		f := v.Elem().FieldByName(name)
		if !f.IsValid() || f.Kind() != reflect.String || !f.CanSet() {
			continue
		}
		if src, ok := m.idMap[f.String()]; ok {
			f.SetString(src)
		}
	}
}

// abandon ends a receive that hasn't happened (the sandbox is being stopped), releasing any
// agent requests waiting for it. No-op once the receive has finished.
func (m *migrationReceive) abandon() {
	m.finish(errors.New("sandbox stopped before the migration was received"))
}

// isTeardownRequest reports agent requests that only clean up guest state. Without a received
// guest there's nothing to clean up, so these succeed rather than failing the sandbox's teardown.
func isTeardownRequest(request interface{}) bool {
	switch request.(type) {
	case *grpc.SignalProcessRequest, *grpc.RemoveContainerRequest,
		*grpc.RemoveStaleVirtiofsShareMountsRequest, *grpc.DestroySandboxRequest:
		return true
	}
	return false
}

// waitReceived blocks agent requests until the VM (and so the agent) has arrived.
func (m *migrationReceive) waitReceived(ctx context.Context) error {
	select {
	case <-m.done:
		return m.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// completeReceive receives the VM once all containers exist, then brings this pod's network and
// the migrated agent into use.
func (s *Sandbox) completeReceive(ctx context.Context) (err error) {
	m := s.migration
	defer func() { m.finish(err) }()

	clh, ok := s.hypervisor.(*cloudHypervisor)
	if !ok {
		return fmt.Errorf("migration receive needs cloud-hypervisor")
	}
	if err = clh.receiveMigration(ctx, m.url, m.srcSandbox); err != nil {
		return err
	}

	k, ok := s.agent.(*kataAgent)
	if !ok {
		return fmt.Errorf("migration receive needs the kata agent")
	}
	m.finish(nil) // let agent requests through
	if err = k.setAgentURL(); err != nil {
		return err
	}
	if err = k.check(ctx); err != nil {
		return err
	}
	// The agent already has a sandbox (CreateSandbox would re-mount its storages), so only
	// update the guest network for this pod's NIC.
	if err = k.setupNetworks(ctx, s); err != nil {
		return err
	}
	migrationLogger().Info("migration received; agent and network ready")
	return nil
}

// receiveMigration receives the VM into the already-launched (but not booted) CH. Its NICs arrive
// with the VM and are re-backed by this pod's taps (cold-attached to clh.netDevices before start).
func (clh *cloudHypervisor) receiveMigration(ctx context.Context, url, srcSandbox string) error {
	ownVfsd, err := clh.virtioFsSocketPath(clh.id)
	if err != nil {
		return err
	}
	ownVsock, err := clh.vsockSocketPath(clh.id)
	if err != nil {
		return err
	}
	// The received config refers to the source sandbox's socket paths. Point the virtiofsd one at
	// our virtiofsd before receiving; CH creates the vsock one, which we link to afterwards.
	srcDir := filepath.Join(clh.config.VMStorePath, srcSandbox)
	srcVfsd := filepath.Join(srcDir, filepath.Base(ownVfsd))
	srcVsock := filepath.Join(srcDir, filepath.Base(ownVsock))
	if srcVfsd != ownVfsd {
		if err := os.MkdirAll(srcDir, DirMode); err != nil {
			return err
		}
		os.Remove(srcVfsd)
		if err := os.Symlink(ownVfsd, srcVfsd); err != nil {
			return err
		}
	}

	// Bound the wait: it blocks every other call on the sandbox (including deletion), since
	// sandbox operations are serialized, and containerd gives the shim's CreateContainer call no
	// deadline. The sender is expected to start soon after the placeholder is waiting.
	// TODO: make the timeout an annotation once a controller drives this.
	migrationLogger().WithField("url", url).Info("waiting to receive migration")
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if err := clh.vmReceiveMigrationWithNetFds(ctx, url); err != nil {
		return err
	}
	info, err := clh.vmInfo()
	if err != nil {
		return err
	}
	if info.State != clhStateRunning {
		return fmt.Errorf("VM state is %q after receiving migration", info.State)
	}
	migrationLogger().Info("migration received, VM running")

	if srcVsock != ownVsock {
		os.Remove(ownVsock)
		if err := os.Symlink(srcVsock, ownVsock); err != nil {
			return err
		}
	}
	return nil
}

// vmReceiveMigrationWithNetFds calls vm.receive-migration, passing this pod's tap FDs for each NIC
// (by the deterministic IDs addNet gives them on both pods) so the migrated NICs are re-backed by
// this pod's network instead of the source's (needs CH >= v55.0 for receive-migration
// external_fds). Hand-rolled like vmAddNetPutRequest: the generated client can't send FDs over
// SCM_RIGHTS.
func (clh *cloudHypervisor) vmReceiveMigrationWithNetFds(ctx context.Context, url string) error {
	type netTarget struct {
		ID string `json:"id"`
	}
	type externalFd struct {
		Target      map[string]netTarget `json:"target"`
		ExpectedFds int                  `json:"expected_fds"`
	}
	body := struct {
		ReceiverURL string       `json:"receiver_url"`
		ExternalFds []externalFd `json:"external_fds,omitempty"`
	}{ReceiverURL: url}
	var fds []int
	if clh.netDevices != nil {
		for _, nd := range *clh.netDevices {
			files := clh.netDevicesFiles[*nd.Mac]
			body.ExternalFds = append(body.ExternalFds, externalFd{
				Target:      map[string]netTarget{"Net": {ID: nd.GetId()}},
				ExpectedFds: len(files),
			})
			for _, f := range files {
				fds = append(fds, int(f.Fd()))
			}
		}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: clh.state.apiSocket, Net: "unix"})
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	req, err := http.NewRequest(http.MethodPut, "http://localhost/api/v1/vm.receive-migration", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// DumpRequest only writes Content-Length from the header (CH rejects a body without it).
	req.Header.Set("Content-Length", strconv.Itoa(len(payload)))
	raw, err := httputil.DumpRequest(req, true)
	if err != nil {
		return err
	}
	if _, _, err := conn.WriteMsgUnix(raw, syscall.UnixRights(fds...), nil); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("vm.receive-migration: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("vm.receive-migration failed with %d: %s", resp.StatusCode, respBody)
	}
	return nil
}
