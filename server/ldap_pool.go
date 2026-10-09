package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/navidrome/navidrome/conf"
)

const (
	defaultLDAPPoolSize      = 4
	defaultLDAPMaxConcurrent = 16
	defaultLDAPTimeout       = 10 * time.Second
	defaultLDAPIdleTimeout   = 15 * time.Minute
	defaultLDAPMaxLifetime   = time.Hour
	maxLDAPPoolSize          = 64
	maxLDAPMaxConcurrent     = 256
)

type ldapSettings struct {
	host, bindDN, bindPassword string
	poolSize, maxConcurrent    int
	timeout, idleTimeout       time.Duration
	maxLifetime                time.Duration
}

func currentLDAPSettings() ldapSettings {
	o := conf.Server.LDAP
	s := ldapSettings{host: o.Host, bindDN: o.BindDN, bindPassword: o.BindPassword,
		poolSize: o.PoolSize, maxConcurrent: o.MaxConcurrent, timeout: o.Timeout,
		idleTimeout: o.IdleTimeout, maxLifetime: o.MaxLifetime}
	if s.poolSize <= 0 {
		s.poolSize = defaultLDAPPoolSize
	} else if s.poolSize > maxLDAPPoolSize {
		s.poolSize = maxLDAPPoolSize
	}
	if s.maxConcurrent <= 0 {
		s.maxConcurrent = defaultLDAPMaxConcurrent
	} else if s.maxConcurrent > maxLDAPMaxConcurrent {
		s.maxConcurrent = maxLDAPMaxConcurrent
	}
	if s.timeout <= 0 {
		s.timeout = defaultLDAPTimeout
	}
	if s.idleTimeout <= 0 {
		s.idleTimeout = defaultLDAPIdleTimeout
	}
	if s.maxLifetime <= 0 {
		s.maxLifetime = defaultLDAPMaxLifetime
	}
	return s
}

type ldapSocket struct {
	conn      ldapConnection
	raw       net.Conn
	createdAt time.Time
	once      sync.Once
}

type ldapConnection interface {
	Bind(username, password string) error
	Search(request *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// abort closes the owned transport first so blocked reads/writes are unblocked,
// then lets go-ldap finish its connection goroutines. The raw close is
// synchronous and idempotent; Conn.Close alone may wait for its internal
// shutdown confirmation while go-ldap's connection goroutines are blocked.
func (c *ldapSocket) abort() {
	if c == nil {
		return
	}
	c.once.Do(func() {
		if c.raw != nil {
			_ = c.raw.Close()
		}
		if c.conn != nil {
			go func() { _ = c.conn.Close() }()
		}
	})
}

func dialLDAP(ctx context.Context, address string) (*ldapSocket, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	host, port := u.Hostname(), u.Port()
	switch u.Scheme {
	case "ldap":
		if port == "" {
			port = ldap.DefaultLdapPort
		}
	case "ldaps":
		if port == "" {
			port = ldap.DefaultLdapsPort
		}
	default:
		return nil, fmt.Errorf("unsupported LDAP URL scheme %q", u.Scheme)
	}
	address = net.JoinHostPort(host, port)
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	isTLS := u.Scheme == "ldaps"
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			_ = raw.Close()
			return nil, err
		}
	}
	if isTLS {
		tlsConn := tls.Client(raw, &tls.Config{ServerName: host})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		raw = tlsConn
	}
	c := ldap.NewConn(raw, isTLS)
	c.Start()
	return &ldapSocket{conn: c, raw: raw, createdAt: time.Now()}, nil
}

type ldapServicePool struct {
	settings ldapSettings
	permits  chan struct{}
	mu       sync.Mutex
	idle     []idleLDAPSocket
	closed   bool
	stop     chan struct{}
	done     chan struct{}
}

type idleLDAPSocket struct {
	socket    *ldapSocket
	idleSince time.Time
}

func newLDAPServicePool(settings ldapSettings) *ldapServicePool {
	p := &ldapServicePool{settings: settings, permits: make(chan struct{}, settings.poolSize), stop: make(chan struct{}), done: make(chan struct{})}
	go p.cleanupLoop()
	return p
}

func (p *ldapServicePool) acquire(ctx context.Context) (*ldapSocket, error) {
	select {
	case p.permits <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		<-p.permits
		return nil, err
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		<-p.permits
		return nil, errors.New("LDAP service connection pool is closed")
	}
	var expired []*ldapSocket
	now := time.Now()
	remaining := p.idle[:0]
	for _, idle := range p.idle {
		if now.Sub(idle.idleSince) >= p.settings.idleTimeout || now.Sub(idle.socket.createdAt) >= p.settings.maxLifetime {
			expired = append(expired, idle.socket)
		} else {
			remaining = append(remaining, idle)
		}
	}
	p.idle = remaining
	// Close stale transports before unlocking so a concurrent acquire cannot
	// open a replacement while the expired physical sockets are still open.
	for _, stale := range expired {
		stale.abort()
	}
	if n := len(p.idle); n > 0 {
		c := p.idle[n-1].socket
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return c, nil
	}
	p.mu.Unlock()
	c, err := dialLDAP(ctx, p.settings.host)
	if err != nil {
		<-p.permits
		return nil, err
	}
	// New pooled service sockets are bound once, here. A reused socket remains
	// service-bound; only its exclusive lease owner may search on it.
	err = withLDAPOperation(ctx, c, func() error { return c.conn.Bind(p.settings.bindDN, p.settings.bindPassword) })
	if err != nil {
		c.abort()
		<-p.permits
		return nil, err
	}
	return c, nil
}

func (p *ldapServicePool) release(c *ldapSocket, reusable bool) {
	if reusable && c != nil {
		p.mu.Lock()
		if !p.closed && time.Since(c.createdAt) < p.settings.maxLifetime {
			p.idle = append(p.idle, idleLDAPSocket{socket: c, idleSince: time.Now()})
			p.mu.Unlock()
			<-p.permits
			return
		}
		p.mu.Unlock()
	}
	if c != nil {
		c.abort()
	}
	<-p.permits
}

func (p *ldapServicePool) cleanupLoop() {
	interval := min(p.settings.idleTimeout/2, p.settings.maxLifetime/2, time.Minute)
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(p.done)
	for {
		select {
		case <-p.stop:
			return
		case now := <-ticker.C:
			var expired []*ldapSocket
			p.mu.Lock()
			remaining := p.idle[:0]
			for _, idle := range p.idle {
				if now.Sub(idle.idleSince) >= p.settings.idleTimeout || now.Sub(idle.socket.createdAt) >= p.settings.maxLifetime {
					expired = append(expired, idle.socket)
				} else {
					remaining = append(remaining, idle)
				}
			}
			p.idle = remaining
			for _, c := range expired {
				c.abort()
			}
			p.mu.Unlock()
		}
	}
}

func (p *ldapServicePool) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		<-p.done
		return
	}
	p.closed = true
	idle := p.idle
	p.idle = nil
	close(p.stop)
	p.mu.Unlock()
	for _, c := range idle {
		c.socket.abort()
	}
	<-p.done
}

type ldapRuntime struct {
	settings ldapSettings
	pool     *ldapServicePool
	requests chan struct{}
}

var ldapRuntimeState struct {
	sync.Mutex
	settings ldapSettings
	runtime  *ldapRuntime
}

func getLDAPRuntime() *ldapRuntime {
	s := currentLDAPSettings()
	ldapRuntimeState.Lock()
	defer ldapRuntimeState.Unlock()
	if ldapRuntimeState.runtime == nil || ldapRuntimeState.settings != s {
		if ldapRuntimeState.runtime != nil {
			ldapRuntimeState.runtime.pool.close()
		}
		ldapRuntimeState.settings = s
		ldapRuntimeState.runtime = &ldapRuntime{settings: s, pool: newLDAPServicePool(s), requests: make(chan struct{}, s.maxConcurrent)}
	}
	return ldapRuntimeState.runtime
}

func (r *ldapRuntime) acquireRequest(ctx context.Context) error {
	select {
	case r.requests <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-r.requests
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *ldapRuntime) releaseRequest() { <-r.requests }

func (r *ldapRuntime) serviceSearch(ctx context.Context, request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	var lastErr error
	// Searching is read-only and idempotent, so one reconnect retry is safe.
	// User binds are intentionally never retried.
	for attempt := 0; attempt < 2; attempt++ {
		c, err := r.pool.acquire(ctx)
		if err != nil {
			return nil, err
		}
		reusable := false
		var result *ldap.SearchResult
		err = withLDAPOperation(ctx, c, func() error {
			var searchErr error
			result, searchErr = c.conn.Search(request)
			return searchErr
		})
		if err == nil {
			reusable = true
		}
		r.pool.release(c, reusable)
		if err == nil {
			return result, nil
		}
		if ctxErr := ldapContextError(ctx, err); ctxErr != nil {
			return nil, ctxErr
		}
		if !ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// withLDAPOperation closes the transport if the request is canceled or times
// out. The caller must discard the socket on any returned error.
func withLDAPOperation(ctx context.Context, socket *ldapSocket, operation func() error) error {
	if err := ctx.Err(); err != nil {
		socket.abort()
		return err
	}
	if socket.raw != nil {
		deadline, ok := ctx.Deadline()
		if !ok {
			deadline = time.Time{}
		}
		if err := socket.raw.SetDeadline(deadline); err != nil {
			socket.abort()
			return err
		}
	}
	done := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			socket.abort()
		case <-done:
		}
	}()
	err := operation()
	close(done)
	<-watcherDone
	ctxErr := ldapContextError(ctx, err)
	if ctxErr != nil {
		socket.abort()
		return ctxErr
	}
	if err == nil && socket.raw != nil {
		if deadlineErr := socket.raw.SetDeadline(time.Time{}); deadlineErr != nil {
			socket.abort()
			return deadlineErr
		}
	}
	return err
}

func ldapContextError(ctx context.Context, operationErr error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if errors.Is(operationErr, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(operationErr, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func bindLDAPUser(ctx context.Context, socket *ldapSocket, dn, password string) error {
	return withLDAPOperation(ctx, socket, func() error { return socket.conn.Bind(dn, password) })
}

// verifyLDAPUserAndAdmin runs the service-account admin query independently
// and concurrently with a user bind on its dedicated connection. Admin errors
// intentionally produce a nil result so callers retain the existing value.
type ldapAdminResult struct {
	isAdmin       bool
	authoritative bool
	err           error
}

func verifyLDAPUserAndAdmin(ctx context.Context, userBind func() error, adminCheck func(context.Context) ldapAdminResult) (*bool, error) {
	if adminCheck == nil {
		return nil, userBind()
	}
	adminCtx, cancelAdmin := context.WithCancel(ctx)
	adminResult := make(chan ldapAdminResult, 1)
	go func() {
		adminResult <- adminCheck(adminCtx)
	}()
	if err := userBind(); err != nil {
		cancelAdmin()
		<-adminResult
		return nil, err
	}
	select {
	case result := <-adminResult:
		cancelAdmin()
		if result.err != nil {
			return nil, result.err
		}
		if !result.authoritative {
			return nil, nil
		}
		return &result.isAdmin, nil
	case <-ctx.Done():
		cancelAdmin()
		<-adminResult
		return nil, ctx.Err()
	}
}
