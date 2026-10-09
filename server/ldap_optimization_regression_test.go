package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/tests"
)

// This TCP fixture records binds and operations per physical connection. It
// deliberately doesn't use the pool's internals: these assertions cover the
// actual LDAP protocol identities used by login and admin lookup.
type optimizationLDAPFixture struct {
	listener    net.Listener
	mu          sync.Mutex
	binds       map[int][]string
	searches    map[int][]string
	next        int
	closed      chan struct{}
	blockBind   string
	blockSearch bool
	blocked     chan struct{}
	adminDN     string
	conns       map[net.Conn]struct{}
	serveWG     sync.WaitGroup
	acceptDone  chan struct{}
}

func startOptimizationLDAPFixture(t *testing.T) *optimizationLDAPFixture {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &optimizationLDAPFixture{listener: l, binds: map[int][]string{}, searches: map[int][]string{}, closed: make(chan struct{}), blocked: make(chan struct{}, 8), conns: map[net.Conn]struct{}{}, acceptDone: make(chan struct{}), adminDN: "uid=alice,dc=test"}
	t.Cleanup(func() {
		_ = l.Close()
		<-f.acceptDone
		f.mu.Lock()
		for c := range f.conns {
			_ = c.Close()
		}
		f.mu.Unlock()
		f.serveWG.Wait()
		<-f.closed
	})
	go func() {
		defer close(f.acceptDone)
		defer close(f.closed)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			f.mu.Lock()
			f.next++
			id := f.next
			f.binds[id] = nil
			f.searches[id] = nil
			f.conns[c] = struct{}{}
			f.serveWG.Add(1)
			f.mu.Unlock()
			go func() {
				defer f.serveWG.Done()
				defer func() { f.mu.Lock(); delete(f.conns, c); f.mu.Unlock() }()
				f.serve(c, id)
			}()
		}
	}()
	return f
}

func (f *optimizationLDAPFixture) addr() string { return "ldap://" + f.listener.Addr().String() }

func (f *optimizationLDAPFixture) snapshot() (map[int][]string, map[int][]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := map[int][]string{}
	s := map[int][]string{}
	for k, v := range f.binds {
		b[k] = append([]string(nil), v...)
	}
	for k, v := range f.searches {
		s[k] = append([]string(nil), v...)
	}
	return b, s
}

func (f *optimizationLDAPFixture) serve(c net.Conn, connID int) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	for {
		p, e := ber.ReadPacket(c)
		if e != nil {
			return
		}
		msgID := p.Children[0].Value.(int64)
		op := p.Children[1]
		write := func(v *ber.Packet) {
			m := ber.NewSequence("LDAP message")
			m.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "ID"))
			m.AppendChild(v)
			_, _ = c.Write(m.Bytes())
		}
		result := func(tag ber.Tag, code int) {
			r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "Result")
			r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "Code"))
			r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "DN"))
			r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Message"))
			write(r)
		}
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			dn := op.Children[1].Value.(string)
			password := string(op.Children[2].Data.Bytes())
			f.mu.Lock()
			f.binds[connID] = append(f.binds[connID], dn)
			blocked := dn == f.blockBind
			f.mu.Unlock()
			if blocked {
				f.blocked <- struct{}{}
				_, _ = c.Read(make([]byte, 1))
				return
			}
			code := ldap.LDAPResultSuccess
			if dn == "cn=service" && password != "service-secret" || dn == "uid=alice,dc=test" && password != "right" {
				code = ldap.LDAPResultInvalidCredentials
			}
			result(ldap.ApplicationBindResponse, code)
		case ldap.ApplicationSearchRequest:
			filter, err := ldap.DecompileFilter(op.Children[6])
			if err != nil {
				return
			}
			f.mu.Lock()
			f.searches[connID] = append(f.searches[connID], filter)
			blockSearch := f.blockSearch && strings.Contains(filter, "memberOf")
			f.mu.Unlock()
			if blockSearch {
				f.blocked <- struct{}{}
				_, _ = c.Read(make([]byte, 1))
				return
			}
			entryDN := "uid=alice,dc=test"
			if strings.Contains(filter, "memberOf") {
				entryDN = f.adminDN
			}
			entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "Entry")
			entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, entryDN, "DN"))
			entry.AppendChild(ber.NewSequence("Attributes"))
			write(entry)
			result(ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess)
		default:
			return
		}
	}
}

func TestLDAPOptimizationCancellationReleasesRequestPermit(t *testing.T) {
	for _, stage := range []string{"user bind", "admin search"} {
		t.Run(stage, func(t *testing.T) {
			f := startOptimizationLDAPFixture(t)
			configureOptimizationLDAP(t, f)
			if stage == "user bind" {
				f.blockBind = "uid=alice,dc=test"
			} else {
				f.blockSearch = true
			}
			conf.Server.LDAP.Timeout = 5 * time.Second
			runtime := getLDAPRuntime()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { _, err := ValidateLogin(ctx, (&tests.MockDataStore{}).User(), "alice", "right"); done <- err }()
			select {
			case <-f.blocked:
			case <-time.After(time.Second):
				cancel()
				t.Fatal("LDAP stage was not reached")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("login error=%v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled LDAP operation did not return promptly")
			}
			if got := len(runtime.requests); got != 0 {
				t.Errorf("request permits still held after cancellation: %d", got)
			}
		})
	}
}

func configureOptimizationLDAP(t *testing.T, f *optimizationLDAPFixture) {
	t.Helper()
	old := conf.Server.LDAP
	t.Cleanup(func() { conf.Server.LDAP = old })
	conf.Server.LDAP.Host = f.addr()
	conf.Server.LDAP.BindDN = "cn=service"
	conf.Server.LDAP.BindPassword = "service-secret"
	conf.Server.LDAP.Base = "dc=test"
	conf.Server.LDAP.SearchFilter = "(uid=%s)"
	conf.Server.LDAP.AdminGroup = "cn=admins"
	conf.Server.LDAP.AdminFilter = ""
	conf.Server.LDAP.PoolSize = 2
	conf.Server.LDAP.MaxConcurrent = 4
	conf.Server.LDAP.Timeout = 2 * time.Second
}

func TestLDAPOptimizationReusesServiceIdentityWithoutSharingUserBind(t *testing.T) {
	f := startOptimizationLDAPFixture(t)
	configureOptimizationLDAP(t, f)
	ds := &tests.MockDataStore{}
	for i := 0; i < 2; i++ {
		u, err := ValidateLogin(context.Background(), ds.User(), "alice", "right")
		if err != nil || u == nil {
			t.Fatalf("login %d: user=%v err=%v", i, u, err)
		}
	}
	binds, searches := f.snapshot()
	serviceBinds, userBinds := 0, 0
	userConnections := map[int]bool{}
	searchConnections := 0
	for id, identities := range binds {
		identitySet := map[string]bool{}
		for _, dn := range identities {
			identitySet[dn] = true
			switch dn {
			case "cn=service":
				serviceBinds++
			case "uid=alice,dc=test":
				userBinds++
				userConnections[id] = true
			default:
				t.Errorf("unexpected bind identity %q", dn)
			}
		}
		if len(identitySet) > 1 {
			t.Errorf("connection %d used multiple bind identities: %v", id, identities)
		}
		if len(identities) > 1 {
			t.Errorf("connection %d has bind identity history %v; want at most one identity", id, identities)
		}
		for _, filter := range searches[id] {
			if len(identities) == 0 || identities[len(identities)-1] != "cn=service" {
				t.Errorf("search %q on non-service-bound conn %d (binds %v)", filter, id, identities)
			}
		}
		if len(searches[id]) > 0 {
			searchConnections++
		}
	}
	if serviceBinds != 1 {
		t.Errorf("service binds=%d, want one across initial and admin searches", serviceBinds)
	}
	if userBinds != 2 {
		t.Errorf("user binds=%d, want one fresh user bind per login", userBinds)
	}
	if searchConnections != 1 {
		t.Errorf("expected only the pooled service connection to search; got %d connections", searchConnections)
	}
	if len(userConnections) != 2 {
		t.Errorf("user binds used %d distinct connections, want 2", len(userConnections))
	}
	for id := range userConnections {
		if len(binds[id]) != 1 {
			t.Errorf("user connection %d bind history=%v, want exactly one bind", id, binds[id])
		}
	}
	for id, filters := range searches {
		if len(filters) > 0 && (len(binds[id]) != 1 || binds[id][0] != "cn=service") {
			t.Errorf("service connection %d bind history=%v, want one service bind", id, binds[id])
		}
	}
}

func TestLDAPOptimizationWrongPasswordIsNotRetriedOrLocallyAccepted(t *testing.T) {
	f := startOptimizationLDAPFixture(t)
	configureOptimizationLDAP(t, f)
	ds := &tests.MockDataStore{}
	if err := ds.User().Put(context.Background(), &model.User{ID: "alice", UserName: "alice", AuthType: model.AuthTypeLDAP, Password: "wrong", NewPassword: "wrong"}); err != nil {
		t.Fatal(err)
	}
	seeded, err := ds.User().FindByUsernameWithPassword(context.Background(), "alice")
	if err != nil || seeded.Password != "wrong" || !seeded.IsLDAP() {
		t.Fatalf("failed to seed matching local fallback credential: user=%+v err=%v", seeded, err)
	}
	u, err := ValidateLogin(context.Background(), ds.User(), "alice", "wrong")
	if err != nil || u != nil {
		t.Fatalf("wrong directory password accepted: user=%v err=%v", u, err)
	}
	binds, _ := f.snapshot()
	userBinds := 0
	for _, identities := range binds {
		for _, dn := range identities {
			if dn == "uid=alice,dc=test" {
				userBinds++
			}
		}
	}
	if userBinds != 1 {
		t.Errorf("wrong user password bind attempts=%d, want exactly one", userBinds)
	}
}

func TestLDAPOptimizationAdminResultMustMatchAuthenticatingDN(t *testing.T) {
	f := startOptimizationLDAPFixture(t)
	configureOptimizationLDAP(t, f)
	f.adminDN = "uid=bob,dc=test"
	u, err := ValidateLogin(context.Background(), (&tests.MockDataStore{}).User(), "alice", "right")
	if err != nil || u == nil {
		t.Fatalf("login: user=%v err=%v", u, err)
	}
	if u.IsAdmin {
		t.Fatal("Alice was granted admin based on another entry's DN")
	}
}

func TestLDAPOptimizationInvalidServiceBindIsNotRetried(t *testing.T) {
	f := startOptimizationLDAPFixture(t)
	configureOptimizationLDAP(t, f)
	conf.Server.LDAP.BindPassword = "invalid-service-secret"
	u, err := ValidateLogin(context.Background(), (&tests.MockDataStore{}).User(), "alice", "right")
	if err != nil || u != nil {
		t.Fatalf("invalid service bind authenticated user: user=%v err=%v", u, err)
	}
	binds, searches := f.snapshot()
	serviceBinds, userBinds, searchCount := 0, 0, 0
	for id, identities := range binds {
		for _, dn := range identities {
			if dn == "cn=service" {
				serviceBinds++
			}
			if dn == "uid=alice,dc=test" {
				userBinds++
			}
		}
		searchCount += len(searches[id])
	}
	if serviceBinds != 1 || userBinds != 0 || searchCount != 0 {
		t.Fatalf("service bind failure activity: service=%d user=%d searches=%d; want 1,0,0", serviceBinds, userBinds, searchCount)
	}
}

func TestLDAPOptimizationCanceledLDAPSHandshakeClosesSocket(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := l.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	defer l.Close()
	old := conf.Server.LDAP
	t.Cleanup(func() { conf.Server.LDAP = old })
	conf.Server.LDAP.Host = "ldaps://" + l.Addr().String()
	conf.Server.LDAP.BindDN = "cn=service"
	conf.Server.LDAP.BindPassword = "secret"
	conf.Server.LDAP.Base = "dc=test"
	conf.Server.LDAP.SearchFilter = "(uid=%s)"
	conf.Server.LDAP.AdminGroup = ""
	conf.Server.LDAP.AdminFilter = ""
	conf.Server.LDAP.PoolSize = 1
	conf.Server.LDAP.MaxConcurrent = 1
	conf.Server.LDAP.Timeout = 150 * time.Millisecond
	start := time.Now()
	u, err := ValidateLogin(context.Background(), (&tests.MockDataStore{}).User(), "alice", "right")
	if err == nil || u != nil {
		t.Fatalf("silent TLS peer result user=%v err=%v; want timeout", u, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("silent TLS handshake took %s", elapsed)
	}
	select {
	case c := <-accepted:
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1024)
		var readErr error
		for readErr == nil {
			_, readErr = c.Read(buf)
		}
		var ne net.Error
		if errors.As(readErr, &ne) && ne.Timeout() {
			t.Fatal("client left silent TLS handshake socket open until peer deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("client never opened TLS socket")
	}
}

type blockedLDAPSyncRepo struct{ model.UserRepository }

func (r blockedLDAPSyncRepo) SyncLDAPLogin(ctx context.Context, _ *model.User, _ bool) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestLDAPOptimizationDatabaseSyncHonorsLDAPDeadline(t *testing.T) {
	f := startOptimizationLDAPFixture(t)
	configureOptimizationLDAP(t, f)
	conf.Server.LDAP.Timeout = 150 * time.Millisecond
	base := (&tests.MockDataStore{}).User()
	seed := &model.User{ID: "alice-id", UserName: "alice", Name: "stale", AuthType: model.AuthTypeLDAP, Password: "right", NewPassword: "right"}
	if err := base.Put(context.Background(), seed); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	u, err := ValidateLogin(context.Background(), blockedLDAPSyncRepo{base}, "alice", "right")
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DB sync result user=%v err=%v; want deadline exceeded", u, err)
	}
	if u != nil {
		t.Fatalf("DB sync cancellation returned authenticated user: %+v", u)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("DB sync cancellation took %s", elapsed)
	}
}
