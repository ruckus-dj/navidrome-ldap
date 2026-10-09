package server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/navidrome/navidrome/conf"
)

func TestLDAPPoolDefaultsAreBounded(t *testing.T) {
	oldPool, oldConcurrent, oldTimeout := conf.Server.LDAP.PoolSize, conf.Server.LDAP.MaxConcurrent, conf.Server.LDAP.Timeout
	oldIdle, oldLifetime := conf.Server.LDAP.IdleTimeout, conf.Server.LDAP.MaxLifetime
	t.Cleanup(func() {
		conf.Server.LDAP.PoolSize, conf.Server.LDAP.MaxConcurrent, conf.Server.LDAP.Timeout = oldPool, oldConcurrent, oldTimeout
		conf.Server.LDAP.IdleTimeout, conf.Server.LDAP.MaxLifetime = oldIdle, oldLifetime
	})
	conf.Server.LDAP.PoolSize, conf.Server.LDAP.MaxConcurrent, conf.Server.LDAP.Timeout = 0, 0, 0
	conf.Server.LDAP.IdleTimeout, conf.Server.LDAP.MaxLifetime = 0, 0
	settings := currentLDAPSettings()
	if settings.poolSize != 4 || settings.maxConcurrent != 16 || settings.timeout != 10*time.Second || settings.idleTimeout != 15*time.Minute || settings.maxLifetime != time.Hour {
		t.Fatalf("unexpected defaults: %+v", settings)
	}
}

func TestLDAPRuntimeBoundsConcurrentRequests(t *testing.T) {
	runtime := &ldapRuntime{requests: make(chan struct{}, 1)}
	if err := runtime.acquireRequest(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.acquireRequest(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquireRequest() error = %v, want context.Canceled", err)
	}
	runtime.releaseRequest()

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.acquireRequest(ctx); err != nil {
		t.Fatalf("acquireRequest() after release: %v", err)
	}
	runtime.releaseRequest()
}

func TestCanceledLDAPOperationClosesTransportAndDoesNotCompleteSuccessfully(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	socket := &ldapSocket{raw: client}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- withLDAPOperation(ctx, socket, func() error {
			_, err := client.Read(make([]byte, 1))
			return err
		})
	}()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("operation error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled LDAP operation did not unblock after transport close")
	}
}

type bindRecorder struct {
	binds  atomic.Int32
	closes atomic.Int32
}

func (b *bindRecorder) Bind(string, string) error {
	b.binds.Add(1)
	return nil
}

func (*bindRecorder) Search(*ldap.SearchRequest) (*ldap.SearchResult, error) { return nil, nil }
func (b *bindRecorder) Close() error                                         { b.closes.Add(1); return nil }

func TestUserBindUsesOnlyItsDedicatedConnection(t *testing.T) {
	serviceConnection, userConnection := &bindRecorder{}, &bindRecorder{}
	user := &ldapSocket{conn: userConnection}
	if err := bindLDAPUser(context.Background(), user, "uid=alice", "directory-secret"); err != nil {
		t.Fatal(err)
	}
	if got := userConnection.binds.Load(); got != 1 {
		t.Fatalf("user connection binds = %d, want 1", got)
	}
	if got := serviceConnection.binds.Load(); got != 0 {
		t.Fatalf("service connection received %d user binds", got)
	}
}

func TestAdminCheckRunsInParallelWithUserBind(t *testing.T) {
	adminStarted := make(chan struct{})
	finishUserBind := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := verifyLDAPUserAndAdmin(context.Background(), func() error {
			<-adminStarted
			close(finishUserBind)
			return nil
		}, func(context.Context) ldapAdminResult {
			close(adminStarted)
			<-finishUserBind
			return ldapAdminResult{isAdmin: true, authoritative: true}
		})
		result <- err
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("admin check and user bind did not make concurrent progress")
	}
}

func TestLDAPUserSyncPropagatesCanceledDatabaseContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := syncLDAPLoginRecord(ctx, nil, "alice", nil, "cn", "mail", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("syncLDAPLoginRecord error = %v, want context.Canceled", err)
	}
}

func TestLDAPPoolExpiresIdleConnectionsAndRetiresActiveOnReturn(t *testing.T) {
	settings := ldapSettings{poolSize: 1, idleTimeout: 40 * time.Millisecond, maxLifetime: time.Second}
	pool := newLDAPServicePool(settings)
	defer pool.close()
	recorder := &bindRecorder{}
	idle := &ldapSocket{conn: recorder, createdAt: time.Now()}
	pool.permits <- struct{}{}
	pool.release(idle, true)
	deadline := time.After(time.Second)
	for recorder.closes.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("idle LDAP connection was not expired")
		case <-time.After(5 * time.Millisecond):
		}
	}

	activeRecorder := &bindRecorder{}
	active := &ldapSocket{conn: activeRecorder, createdAt: time.Now()}
	pool.permits <- struct{}{}
	pool.close()
	if got := activeRecorder.closes.Load(); got != 0 {
		t.Fatalf("pool shutdown closed an active leased connection: closes=%d", got)
	}
	pool.release(active, true)
	deadline = time.After(time.Second)
	for activeRecorder.closes.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("retired pool did not close connection on return")
		case <-time.After(5 * time.Millisecond):
		}
	}
}
