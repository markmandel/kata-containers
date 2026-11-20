// Copyright (c) 2026 Agones Authors
//
// SPDX-License-Identifier: Apache-2.0
//

// Experimental live-migration "send" side for a Cloud Hypervisor sandbox (the source pod).
//
// MigrateOut asks CH to send the running VM to a receiver (a placeholder pod's CH, see
// migration.go) and waits for the outcome from CH's event log. Once the VM has left, the shim must
// not treat it as a crash: the VM and its containers keep running on the destination. So while
// sending and afterwards, hypervisor/agent health checks report healthy and a virtiofsd exit
// doesn't stop the sandbox. After a successful send, container waits stay blocked (kubelet keeps
// seeing the containers running, so it doesn't restart them here) until the pod is deleted, and
// teardown requests succeed without an agent.

package virtcontainers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/agent/protocols/grpc"
	chclient "github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/cloud-hypervisor/client"
)

// clhEventsFile is CH's event log in the VM directory (--event-monitor).
const clhEventsFile = "clh-events.json"

const (
	sendIdle = iota
	sendSending
	sendMigrated
)

var errMigratedOut = errors.New("sandbox VM has been live-migrated away")

type migrationSend struct {
	mu       sync.Mutex
	state    int
	teardown chan struct{} // closed when the sandbox starts stopping
	once     sync.Once
}

func newMigrationSend() *migrationSend {
	return &migrationSend{teardown: make(chan struct{})}
}

func (m *migrationSend) get() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *migrationSend) set(state int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state = state
}

// active reports whether the VM is leaving or has left; nil-safe.
func (m *migrationSend) active() bool { return m != nil && m.get() != sendIdle }

func (m *migrationSend) migrated() bool { return m != nil && m.get() == sendMigrated }

func (m *migrationSend) beginTeardown() {
	if m != nil {
		m.once.Do(func() { close(m.teardown) })
	}
}

// isLongPollRequest reports agent requests that block until something happens in the guest.
func isLongPollRequest(request interface{}) bool {
	switch request.(type) {
	case *grpc.WaitProcessRequest, *grpc.GetOOMEventRequest:
		return true
	}
	return false
}

// gate decides agent requests for a sandbox whose VM is leaving or has left. handled reports
// whether the request was answered here instead of being sent to the agent.
func (m *migrationSend) gate(ctx context.Context, request interface{}) (handled bool, err error) {
	if !m.active() {
		return false, nil
	}
	if _, ok := request.(*grpc.CheckRequest); ok {
		return true, nil
	}
	if !m.migrated() {
		return false, nil // still sending: the agent is still here
	}
	if isTeardownRequest(request) {
		// kubelet signals containers first when deleting the pod, then waits for them to exit.
		// Their waits are held until teardown, so a signal is what starts it.
		if _, ok := request.(*grpc.SignalProcessRequest); ok {
			m.beginTeardown()
		}
		return true, nil
	}
	if isLongPollRequest(request) {
		return true, m.waitTeardown(ctx)
	}
	return true, errMigratedOut
}

// afterFailure keeps long-polls that broke because the VM left blocked, as if the process were
// still running, until the pod is torn down.
func (m *migrationSend) afterFailure(ctx context.Context, request interface{}, err error) error {
	if err == nil || !m.active() || !isLongPollRequest(request) {
		return err
	}
	if werr := m.waitTeardown(ctx); werr != nil {
		return werr
	}
	return err
}

func (m *migrationSend) waitTeardown(ctx context.Context) error {
	select {
	case <-m.teardown:
		return errMigratedOut
	case <-ctx.Done():
		return ctx.Err()
	}
}

// MigrateOut live-migrates this sandbox's VM to dest (host:port of the receiver) and waits for
// CH to report the outcome. On failure CH resumes the VM here and the sandbox carries on.
func (s *Sandbox) MigrateOut(ctx context.Context, dest string, timeout time.Duration) error {
	clh, ok := s.hypervisor.(*cloudHypervisor)
	if !ok {
		return fmt.Errorf("live migration needs cloud-hypervisor")
	}
	m := s.migrationOut
	m.mu.Lock()
	if m.state != sendIdle {
		m.mu.Unlock()
		return fmt.Errorf("a migration is already in progress or done")
	}
	m.state = sendSending
	m.mu.Unlock()

	migrationLogger().WithField("dest", dest).Info("sending migration")
	if err := clh.sendMigration(ctx, dest, timeout); err != nil {
		m.set(sendIdle)
		migrationLogger().WithError(err).Warn("migration failed; VM stays here")
		return err
	}
	m.set(sendMigrated)
	migrationLogger().Info("migration sent; VM now runs on the destination")
	return nil
}

// sendMigration starts vm.send-migration to a UNIX socket that the shim relays to dest over TCP
// (CH runs in the pod netns, whose traffic is redirected into the VM), then follows CH's event
// log until the migration finishes or fails.
func (clh *cloudHypervisor) sendMigration(ctx context.Context, dest string, timeout time.Duration) error {
	vmPath := filepath.Join(clh.config.VMStorePath, clh.id)
	relay := filepath.Join(vmPath, "migrate-out.sock")
	os.Remove(relay)
	l, err := net.Listen("unix", relay)
	if err != nil {
		return err
	}
	defer l.Close()
	go relayConnections(l, dest)

	events := filepath.Join(vmPath, clhEventsFile)
	offset := int64(0)
	if fi, err := os.Stat(events); err == nil {
		offset = fi.Size()
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	api, ok := clh.client().(*clhClientApi)
	if !ok {
		return fmt.Errorf("unexpected cloud-hypervisor client type %T", clh.client())
	}
	if _, err := api.ApiInternal.VmSendMigrationPut(ctx).
		SendMigrationData(*chclient.NewSendMigrationData("unix:" + relay)).Execute(); err != nil {
		return openAPIClientError(err)
	}

	for {
		if outcome := migrationOutcome(events, offset); outcome != "" {
			if outcome == "migration-finished" {
				return nil
			}
			return fmt.Errorf("cloud-hypervisor reported %s", outcome)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for the migration to finish: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// migrationOutcome returns the first migration-finished/-failed/-cancelled event logged after
// offset, or "".
func migrationOutcome(events string, offset int64) string {
	f, err := os.Open(events)
	if err != nil {
		return ""
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return ""
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return ""
	}
	first, firstAt := "", -1
	for _, ev := range []string{"migration-finished", "migration-failed", "migration-cancelled"} {
		i := bytes.Index(data, []byte(`"event": "`+ev+`"`))
		if i < 0 {
			i = bytes.Index(data, []byte(`"event":"`+ev+`"`))
		}
		if i >= 0 && (firstAt < 0 || i < firstAt) {
			first, firstAt = ev, i
		}
	}
	return strings.TrimSpace(first)
}

// relayConnections pipes each connection accepted on l to a new TCP connection to dest.
func relayConnections(l net.Listener, dest string) {
	for {
		in, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer in.Close()
			out, err := net.Dial("tcp", dest)
			if err != nil {
				migrationLogger().WithError(err).WithField("dest", dest).Error("migration relay")
				return
			}
			defer out.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(out, in); closeWrite(out); done <- struct{}{} }()
			go func() { io.Copy(in, out); closeWrite(in); done <- struct{}{} }()
			<-done
			<-done
		}()
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}
