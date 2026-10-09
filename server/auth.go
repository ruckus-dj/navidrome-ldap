package server

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/deluan/rest"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-ldap/ldap/v3"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/consts"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/id"
	"github.com/navidrome/navidrome/model/request"
	"github.com/navidrome/navidrome/utils/gravatar"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	ErrNoUsers         = errors.New("no users created")
	ErrUnauthenticated = errors.New("request not authenticated")
)

func login(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, err := getCredentialsFromBody(r)
		if err != nil {
			log.Error(r, "Parsing request body", err)
			_ = rest.RespondWithError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}

		doLogin(ds, username, password, w, r)
	}
}

func doLogin(ds model.DataStore, username string, password string, w http.ResponseWriter, r *http.Request) {
	user, err := ValidateLogin(r.Context(), ds.User(), username, password)
	if err != nil {
		_ = rest.RespondWithError(w, http.StatusInternalServerError, "Unknown error authentication user. Please try again")
		return
	}
	if user == nil {
		log.Warn(r, "Unsuccessful login", "username", username, "request", r.Header)
		_ = rest.RespondWithError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	tokenString, err := auth.CreateToken(user)
	if err != nil {
		_ = rest.RespondWithError(w, http.StatusInternalServerError, "Unknown error authenticating user. Please try again")
		return
	}
	payload := buildAuthPayload(user)
	payload["token"] = tokenString
	_ = rest.RespondWithJSON(w, http.StatusOK, payload)
}

func buildAuthPayload(user *model.User) map[string]any {
	payload := map[string]any{
		"id":       user.ID,
		"name":     user.Name,
		"username": user.UserName,
		"isAdmin":  user.IsAdmin,
	}
	if conf.Server.EnableGravatar && user.Email != "" {
		payload["avatar"] = gravatar.Url(user.Email, 50)
	}

	bytes := make([]byte, 3)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Error("Could not create subsonic salt", "user", user.UserName, err)
		return payload
	}
	subsonicSalt := hex.EncodeToString(bytes)
	payload["subsonicSalt"] = subsonicSalt

	subsonicToken := md5.Sum([]byte(user.Password + subsonicSalt))
	payload["subsonicToken"] = hex.EncodeToString(subsonicToken[:])

	return payload
}

// MaxLoginBodySize bounds the payload of unauthenticated login routes across all APIs.
const MaxLoginBodySize = 8 << 10

func LimitLoginBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxLoginBodySize)
		next.ServeHTTP(w, r)
	})
}

func getCredentialsFromBody(r *http.Request) (username string, password string, err error) {
	data := make(map[string]string)
	decoder := json.NewDecoder(r.Body)
	if err = decoder.Decode(&data); err != nil {
		log.Error(r, "parsing request body", err)
		err = errors.New("invalid request payload")
		return
	}
	username = data["username"]
	password = data["password"]
	return username, password, nil
}

func createAdmin(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, err := getCredentialsFromBody(r)
		if err != nil {
			log.Error(r, "parsing request body", err)
			_ = rest.RespondWithError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		c, err := ds.User().CountAll(r.Context())
		if err != nil {
			_ = rest.RespondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if c > 0 {
			_ = rest.RespondWithError(w, http.StatusForbidden, "Cannot create another first admin")
			return
		}
		err = createAdminUser(r.Context(), ds, username, password)
		if err != nil {
			_ = rest.RespondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		doLogin(ds, username, password, w, r)
	}
}

func createAdminUser(ctx context.Context, ds model.DataStore, username, password string) error {
	log.Warn(ctx, "Creating initial user", "user", username)
	caser := cases.Title(language.Und)
	initialUser := model.User{
		ID:          id.NewRandom(),
		UserName:    username,
		Name:        caser.String(username),
		Email:       "",
		NewPassword: password,
		IsAdmin:     true,
		LastLoginAt: new(time.Now()),
	}
	err := ds.User().Put(ctx, &initialUser)
	if err != nil {
		log.Error(ctx, "Could not create initial user", "user", initialUser.UserName, err)
		return fmt.Errorf("creating initial user: %w", err)
	}
	return nil
}

func ValidateLogin(ctx context.Context, userRepo model.UserRepository, userName, password string) (*model.User, error) {
	// Empty passwords never authenticate. LDAP-backed users have an empty
	// `password` column (cleared by ClearPassword on every login), so an
	// empty submitted password would otherwise match the empty stored one
	// in the local fallback below.
	if password == "" {
		return nil, nil
	}
	u, err := validateLoginLDAP(ctx, userRepo, userName, password)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if u != nil && err == nil {
		return u, nil
	}
	u, err = userRepo.FindByUsernameWithPassword(ctx, userName)
	if errors.Is(err, model.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// LDAP-backed users have no valid local password. If we reached this
	// point for one (LDAP unreachable, directory bind failed, etc.), refuse
	// rather than fall through to the local-password compare.
	if u.IsLDAP() || u.Password == "" {
		return nil, nil
	}
	if u.Password != password {
		return nil, nil
	}
	err = userRepo.UpdateLastLoginAt(ctx, u.ID)
	if err != nil {
		log.Error(ctx, "Could not update LastLoginAt", "user", userName)
	}
	return u, nil
}

func validateLoginLDAP(ctx context.Context, userRepo model.UserRepository, userName, password string) (*model.User, error) {
	if conf.Server.LDAP.Host == "" {
		return nil, nil
	}

	runtime := getLDAPRuntime()
	ldapCtx, cancel := context.WithTimeout(ctx, runtime.settings.timeout)
	defer cancel()
	started := time.Now()
	defer func() { log.Debug(ldapCtx, "LDAP authentication completed", "duration", time.Since(started)) }()
	if err := runtime.acquireRequest(ldapCtx); err != nil {
		return nil, err
	}
	defer runtime.releaseRequest()

	mailAttr := conf.Server.LDAP.Mail
	nameAttr := conf.Server.LDAP.Name

	searchRequest := ldap.NewSearchRequest(
		conf.Server.LDAP.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(conf.Server.LDAP.SearchFilter, ldap.EscapeFilter(userName)),
		[]string{"dn", nameAttr, mailAttr},
		nil,
	)
	phase := time.Now()
	sr, err := runtime.serviceSearch(ldapCtx, searchRequest)
	if err != nil {
		if ctxErr := ldapContextError(ldapCtx, err); ctxErr != nil {
			return nil, ctxErr
		}
		log.Error("LDAP search failed", "user", userName, err)
		return nil, nil
	}
	log.Debug(ctx, "LDAP user search completed", "duration", time.Since(phase))
	if len(sr.Entries) != 1 {
		log.Warn("LDAP search returned unexpected number of entries", "user", userName, "matches", len(sr.Entries))
		return nil, nil
	}

	entry := sr.Entries[0]

	// Group membership queries may only be readable by the service account.
	// Search has completed; run the independent service-account query in
	// parallel with a fresh user connection so neither credential can leak
	// into the other's connection.
	var adminCheck func(context.Context) ldapAdminResult
	if !adminCheckEnabled() {
		adminCheck = nil
	} else {
		adminCheck = func(searchCtx context.Context) ldapAdminResult {
			adminStarted := time.Now()
			isAdmin, searchErr := ldapAdminLookup(searchCtx, runtime, userName, entry.DN)
			log.Debug(searchCtx, "LDAP admin search completed", "duration", time.Since(adminStarted))
			if searchErr != nil {
				if ctxErr := ldapContextError(searchCtx, searchErr); ctxErr != nil {
					return ldapAdminResult{err: ctxErr}
				}
				log.Warn(searchCtx, "LDAP admin lookup failed; preserving existing IsAdmin", "user", userName, searchErr)
				return ldapAdminResult{}
			}
			return ldapAdminResult{isAdmin: isAdmin, authoritative: true}
		}
	}

	phase = time.Now()
	adminCheckResult, userBindErr := verifyLDAPUserAndAdmin(ldapCtx, func() error {
		userConn, dialErr := dialLDAP(ldapCtx, runtime.settings.host)
		if dialErr != nil {
			return dialErr
		}
		defer userConn.abort()
		return bindLDAPUser(ldapCtx, userConn, entry.DN, password)
	}, adminCheck)
	log.Debug(ldapCtx, "LDAP user bind and admin check completed", "duration", time.Since(phase))
	if userBindErr != nil {
		if ctxErr := ldapContextError(ldapCtx, userBindErr); ctxErr != nil {
			return nil, ctxErr
		}
		log.Error("LDAP user connection or bind failed", "user", userName, userBindErr)
		log.Warn("LDAP user authentication failed", "user", userName, userBindErr)
		return nil, nil
	}
	if ctxErr := ldapContextError(ldapCtx, nil); ctxErr != nil {
		return nil, ctxErr
	}

	return syncLDAPLoginRecord(ldapCtx, userRepo, userName, entry, nameAttr, mailAttr, adminCheckResult)
}

func ldapAdminLookup(ctx context.Context, runtime *ldapRuntime, userName, authenticatedDN string) (bool, error) {
	request := ldap.NewSearchRequest(conf.Server.LDAP.Base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, buildAdminFilter(userName), []string{"dn"}, nil)
	result, err := runtime.serviceSearch(ctx, request)
	if err != nil {
		return false, err
	}
	return ldapAdminResultForDN(result, authenticatedDN)
}

func syncLDAPLoginRecord(ctx context.Context, userRepo model.UserRepository, userName string, entry *ldap.Entry, nameAttr, mailAttr string, adminCheckResult *bool) (*model.User, error) {
	if ctxErr := ldapContextError(ctx, nil); ctxErr != nil {
		return nil, ctxErr
	}
	u, err := userRepo.FindByUsername(ctx, userName)
	if errors.Is(err, model.ErrNotFound) {
		u = &model.User{UserName: userName}
	} else if err != nil {
		if ctxErr := ldapContextError(ctx, err); ctxErr != nil {
			return nil, ctxErr
		}
		log.Error(ctx, "Could not look up LDAP user in DB", "user", userName, err)
		return nil, nil
	}
	newName, newEmail := entry.GetAttributeValue(nameAttr), entry.GetAttributeValue(mailAttr)
	changed := u.Name != newName || u.Email != newEmail || u.AuthType != model.AuthTypeLDAP
	u.Name, u.Email, u.AuthType = newName, newEmail, model.AuthTypeLDAP
	oldAdmin := u.IsAdmin
	applyLDAPAdminResult(u, adminCheckResult)
	changed = changed || oldAdmin != u.IsAdmin
	if u.ID == "" {
		err = userRepo.Put(ctx, u)
	} else if changed || u.IsAdmin {
		err = userRepo.SyncLDAPLogin(ctx, u, adminCheckResult != nil)
	}
	if err != nil {
		if ctxErr := ldapContextError(ctx, err); ctxErr != nil {
			return nil, ctxErr
		}
		log.Error(ctx, "Could not save LDAP user", "user", userName, err)
		return nil, nil
	}
	if u.Password != "" {
		if err := userRepo.ClearPassword(ctx, u.ID); err != nil {
			if ctxErr := ldapContextError(ctx, err); ctxErr != nil {
				return nil, ctxErr
			}
			log.Error(ctx, "Could not clear persisted password for LDAP user", "user", userName, err)
			return nil, nil
		}
	}
	u.Password = ""
	if err := userRepo.UpdateLastLoginAt(ctx, u.ID); err != nil {
		if ctxErr := ldapContextError(ctx, err); ctxErr != nil {
			return nil, ctxErr
		}
		log.Error(ctx, "Could not update LastLoginAt", "user", userName, err)
	}
	if ctxErr := ldapContextError(ctx, nil); ctxErr != nil {
		return nil, ctxErr
	}
	return u, nil
}

func JWTVerifier(next http.Handler) http.Handler {
	return jwtauth.Verify(auth.TokenAuth, tokenFromHeader, jwtauth.TokenFromCookie, jwtauth.TokenFromQuery)(next)
}

func tokenFromHeader(r *http.Request) string {
	// Get token from authorization header.
	bearer := r.Header.Get(consts.UIAuthorizationHeader)
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

func UsernameFromToken(r *http.Request) string {
	token, _, err := jwtauth.FromContext(r.Context())
	if err != nil || token == nil {
		return ""
	}
	sub, _ := token.Subject()
	if sub == "" {
		return ""
	}
	log.Trace(r, "Found username in JWT token", "username", sub)
	return sub
}

func UsernameFromExtAuthHeader(r *http.Request) string {
	if conf.Server.ExtAuth.TrustedSources == "" {
		return ""
	}
	reverseProxyIp, ok := request.ReverseProxyIpFrom(r.Context())
	if !ok {
		log.Error("ExtAuth enabled but no proxy IP found in request context. Please report this error.")
		return ""
	}
	username := r.Header.Get(conf.Server.ExtAuth.UserHeader)
	if username == "" {
		return ""
	}
	if !validateIPAgainstList(reverseProxyIp, conf.Server.ExtAuth.TrustedSources) {
		log.Warn(r.Context(), "IP is not whitelisted for external authentication", "proxy-ip", reverseProxyIp, "client-ip", r.RemoteAddr)
		return ""
	}
	log.Trace(r, "Found username in ExtAuth.UserHeader", "username", username)
	return username
}

func InternalAuth(r *http.Request) string {
	username, ok := request.InternalAuthFrom(r.Context())
	if !ok {
		return ""
	}
	log.Trace(r, "Found username in InternalAuth", "username", username)
	return username
}

func UsernameFromConfig(*http.Request) string {
	return conf.Server.DevAutoLoginUsername
}

func contextWithUser(ctx context.Context, ds model.DataStore, username string) (context.Context, error) {
	user, err := ds.User().FindByUsername(ctx, username)
	if err == nil {
		ctx = log.NewContext(ctx, "username", username)
		ctx = request.WithUsername(ctx, user.UserName)
		return request.WithUser(ctx, *user), nil
	}
	log.Error(ctx, "Authenticated username not found in DB", "username", username)
	return ctx, err
}

func authenticateRequest(ds model.DataStore, r *http.Request, findUsernameFns ...func(r *http.Request) string) (context.Context, error) {
	var username string
	for _, fn := range findUsernameFns {
		username = fn(r)
		if username != "" {
			break
		}
	}
	if username == "" {
		return nil, ErrUnauthenticated
	}

	return contextWithUser(r.Context(), ds, username)
}

func Authenticator(ds model.DataStore) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, err := authenticateRequest(ds, r, UsernameFromConfig, UsernameFromToken, UsernameFromExtAuthHeader)
			if err != nil || !tokenAllowed(ctx) {
				_ = rest.RespondWithError(w, http.StatusUnauthorized, "Not authenticated")
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// tokenAllowed re-checks a JWT that actually identifies the resolved user. Header and
// config auth carry no token, so they short-circuit to true.
func tokenAllowed(ctx context.Context) bool {
	token, _, err := jwtauth.FromContext(ctx)
	if err != nil || token == nil {
		return true
	}
	usr, ok := request.UserFrom(ctx)
	if !ok {
		return true
	}
	claims := auth.ClaimsFromToken(token)
	if !strings.EqualFold(claims.Subject, usr.UserName) {
		return true
	}
	if err := auth.CheckClaims(claims, usr, auth.AudienceNative); err != nil {
		log.Warn(ctx, "Native API: rejected token", "user", claims.Subject, err)
		return false
	}
	return true
}

// refreshingWriter defers the refreshed-token header until the handler's first write, so an
// epoch the handler bumped reaches the token the client stores.
type refreshingWriter struct {
	http.ResponseWriter
	ctx   context.Context //nolint:containedctx // ResponseWriter wrapper defers work to Write, which has no ctx
	token jwt.Token
	once  sync.Once
}

func (w *refreshingWriter) setToken() {
	w.once.Do(func() {
		claims := auth.ClaimsFromToken(w.token)
		if epoch, ok := request.TokenEpochFrom(w.ctx); ok {
			claims.Epoch = epoch
		}
		newToken, err := auth.TouchClaims(claims)
		if err != nil {
			log.Error(w.ctx, "Could not sign new token", err)
			return
		}
		w.Header().Set(consts.UIAuthorizationHeader, newToken)
	})
}

func (w *refreshingWriter) WriteHeader(code int) {
	w.setToken()
	w.ResponseWriter.WriteHeader(code)
}

func (w *refreshingWriter) Write(b []byte) (int, error) {
	w.setToken()
	return w.ResponseWriter.Write(b)
}

// Flush keeps the SSE events route working through the wrap.
func (w *refreshingWriter) Flush() {
	w.setToken()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets capability lookups, such as SSE's write deadline, see past this wrap.
func (w *refreshingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// JWTRefresher updates the expiry date of the received JWT token, and adds the new one to
// the Authorization Header.
func JWTRefresher(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _, err := jwtauth.FromContext(r.Context())
		if err != nil || token == nil {
			next.ServeHTTP(w, r)
			return
		}
		ctx := request.WithTokenEpochHolder(r.Context())
		rw := &refreshingWriter{ResponseWriter: w, ctx: ctx, token: token}
		next.ServeHTTP(rw, r.WithContext(ctx))
		rw.setToken()
	})
}

func handleLoginFromHeaders(ds model.DataStore, r *http.Request) map[string]any {
	username := UsernameFromConfig(r)
	if username == "" {
		username = UsernameFromExtAuthHeader(r)
		if username == "" {
			return nil
		}
	}

	ctx := r.Context()
	userRepo := ds.User()
	user, err := userRepo.FindByUsernameWithPassword(ctx, username)
	if user == nil || err != nil {
		log.Info(r, "User passed in header not found", "user", username)
		// Check if this is the first user being created
		count, _ := userRepo.CountAll(ctx)
		isFirstUser := count == 0

		newUser := model.User{
			ID:          id.NewRandom(),
			UserName:    username,
			Name:        username,
			Email:       "",
			NewPassword: consts.PasswordAutogenPrefix + id.NewRandom(),
			IsAdmin:     isFirstUser, // Make the first user an admin
		}
		err := userRepo.Put(ctx, &newUser)
		if err != nil {
			log.Error(r, "Could not create new user", "user", username, err)
			return nil
		}
		user, err = userRepo.FindByUsernameWithPassword(ctx, username)
		if user == nil || err != nil {
			log.Error(r, "Created user but failed to fetch it", "user", username)
			return nil
		}
	}

	err = userRepo.UpdateLastLoginAt(ctx, user.ID)
	if err != nil {
		log.Error(r, "Could not update LastLoginAt", "user", username, err)
		return nil
	}

	return buildAuthPayload(user)
}

func validateIPAgainstList(ip string, comaSeparatedList string) bool {
	if comaSeparatedList == "" || ip == "" {
		return false
	}

	cidrs := strings.Split(comaSeparatedList, ",")

	// Per https://github.com/golang/go/issues/49825, the remote address
	// on a unix socket is '@'
	if ip == "@" && strings.HasPrefix(conf.Server.Address, "unix:") {
		return slices.Contains(cidrs, "@")
	}

	if net.ParseIP(ip) == nil {
		ip, _, _ = net.SplitHostPort(ip)
	}

	if ip == "" {
		return false
	}

	testedIP, _, err := net.ParseCIDR(fmt.Sprintf("%s/32", ip))
	if err != nil {
		return false
	}

	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil && ipnet.Contains(testedIP) {
			return true
		}
	}

	return false
}
