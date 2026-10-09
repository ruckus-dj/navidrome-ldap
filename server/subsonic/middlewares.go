package subsonic

import (
	"cmp"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	ua "github.com/mileusna/useragent"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/consts"
	"github.com/navidrome/navidrome/core"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/core/metrics"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/request"
	"github.com/navidrome/navidrome/server"
	"github.com/navidrome/navidrome/server/subsonic/responses"
	. "github.com/navidrome/navidrome/utils/gg"
	"github.com/navidrome/navidrome/utils/req"
)

func postFormToQueryParams(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB
		err := r.ParseForm()
		if err != nil {
			sendError(w, r, newError(responses.ErrorGeneric, err.Error()))
			return
		}
		var parts []string
		for key, values := range r.Form {
			for _, v := range values {
				parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(v))
			}
		}
		r.URL.RawQuery = strings.Join(parts, "&")

		next.ServeHTTP(w, r)
	})
}

func fromInternalOrProxyAuth(r *http.Request) (string, bool) {
	username := server.InternalAuth(r)

	// If the username comes from internal auth, do not also do reverse proxy auth, as
	// the request will have no reverse proxy IP
	if username != "" {
		return username, true
	}

	return server.UsernameFromExtAuthHeader(r), false
}

func checkRequiredParameters(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requiredParameters []string

		p := req.Params(r)
		username, _ := fromInternalOrProxyAuth(r)
		apiKey, _ := p.String("apiKey")
		if username != "" || apiKey != "" {
			requiredParameters = []string{"v", "c"}
		} else {
			requiredParameters = []string{"u", "v", "c"}
		}

		for _, param := range requiredParameters {
			if _, err := p.String(param); err != nil {
				log.Warn(r, err)
				sendError(w, r, err)
				return
			}
		}

		if username == "" {
			username, _ = p.String("u")
		}
		client, _ := p.String("c")
		version, _ := p.String("v")

		ctx := r.Context()
		ctx = request.WithUsername(ctx, username)
		ctx = request.WithClient(ctx, client)
		ctx = request.WithVersion(ctx, version)
		log.Debug(ctx, "API: New request "+r.URL.Path, "username", username, "client", client, "version", version)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func authenticate(ds model.DataStore) func(next http.Handler) http.Handler {
	limiter := newAuthLimiter(conf.Server.AuthRequestLimit, conf.Server.AuthWindowLength)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			var usr *model.User
			var keyPlayer *model.Player
			var err error

			p := req.Params(r)
			apiKey, _ := p.String("apiKey")
			username, isInternalAuth := fromInternalOrProxyAuth(r)
			switch {
			case username != "":
				authType := If(isInternalAuth, "internal", "reverse-proxy")
				usr, err = ds.User().FindByUsername(ctx, username)
				if errors.Is(err, context.Canceled) {
					log.Debug(ctx, "API: Request canceled when authenticating", "auth", authType, "username", username, "remoteAddr", r.RemoteAddr, err)
					return
				}
				if errors.Is(err, model.ErrNotFound) {
					log.Warn(ctx, "API: Invalid login", "auth", authType, "username", username, "remoteAddr", r.RemoteAddr, err)
				} else if err != nil {
					log.Error(ctx, "API: Error authenticating username", "auth", authType, "username", username, "remoteAddr", r.RemoteAddr, err)
				}
			case apiKey != "":
				usr, keyPlayer, err = authenticateAPIKey(ctx, ds, limiter, r, apiKey)
				if err != nil {
					if ctx.Err() == nil {
						sendError(w, r, err)
					}
					return
				}
				ctx = request.WithUsername(ctx, usr.UserName)
			default:
				var handled bool
				usr, keyPlayer, err, handled = authenticateSubsonicCredentials(ds, limiter, w, r)
				if handled {
					return
				}
			}

			if err != nil {
				sendError(w, r, newError(responses.ErrorAuthenticationFail))
				return
			}

			ctx = request.WithUser(ctx, *usr)
			if keyPlayer != nil {
				ctx = request.WithPlayer(ctx, *keyPlayer)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func authenticateSubsonicCredentials(ds model.DataStore, limiter *authLimiter, w http.ResponseWriter, r *http.Request) (*model.User, *model.Player, error, bool) {
	ctx := r.Context()
	p := req.Params(r)
	username, _ := p.String("u")
	pass, _ := p.String("p")
	if strings.HasPrefix(pass, "enc:") {
		if dec, err := hex.DecodeString(pass[4:]); err == nil {
			pass = string(dec)
		}
	}
	token, _ := p.String("t")
	salt, _ := p.String("s")
	jwt, _ := p.String("jwt")

	// Blocked attempts get the same response as a wrong password, so they reveal nothing.
	limitKey := server.ClientIP(r) + "\x00" + strings.ToLower(username)
	slot, allowed := limiter.acquire(ctx, limitKey)
	if !allowed {
		if err := ctx.Err(); err != nil {
			return nil, nil, err, true
		}
		log.Warn(ctx, "API: Too many failed login attempts", "auth", "subsonic", "username", username, "remoteAddr", r.RemoteAddr)
		sendError(w, r, newError(responses.ErrorAuthenticationFail))
		return nil, nil, nil, true
	}

	// App-password fast path avoids hitting LDAP for every Subsonic request.
	// LDAP users can still use legacy p= auth via the live bind below.
	if jwt == "" && (pass != "" || token != "") {
		lookupUsr, appID, ok := matchAppPassword(ctx, ds, username, pass, token, salt)
		if ok {
			if touchErr := ds.AppPassword().Touch(ctx, appID); touchErr != nil {
				log.Warn(ctx, "API: Failed to bump app password last_used_at", "id", appID, "username", username, touchErr)
			}
			slot.release(false)
			// The helper's caller invokes the continuation after successful auth.
			return lookupUsr, nil, nil, false
		}
		if lookupUsr != nil && lookupUsr.IsLDAP() && pass == "" {
			log.Warn(ctx, "API: Rejecting non-app-password token auth for LDAP user", "username", username, "remoteAddr", r.RemoteAddr)
			slot.release(true)
			sendError(w, r, newError(responses.ErrorAuthenticationFail))
			return nil, nil, nil, true
		}
	}

	usr, keyPlayer, err := authenticateSubsonicPassword(ctx, ds, username, pass, token, salt, jwt)
	invalidLogin := errors.Is(err, model.ErrNotFound) || errors.Is(err, model.ErrInvalidAuth)
	slot.release(invalidLogin)
	switch {
	case errors.Is(err, context.Canceled):
		log.Debug(ctx, "API: Request canceled when authenticating", "auth", "subsonic", "username", username, "remoteAddr", r.RemoteAddr, err)
		return nil, nil, nil, true
	case invalidLogin:
		log.Warn(ctx, "API: Invalid login", "auth", "subsonic", "username", username, "remoteAddr", r.RemoteAddr, err)
	case err != nil:
		log.Error(ctx, "API: Error authenticating username", "auth", "subsonic", "username", username, "remoteAddr", r.RemoteAddr, err)
	}
	return usr, keyPlayer, err, false
}

func authenticateSubsonicPassword(ctx context.Context, ds model.DataStore, username, pass, token, salt, jwt string) (*model.User, *model.Player, error) {
	var usr *model.User
	var keyPlayer *model.Player
	var err error
	if pass != "" {
		// Player API keys are credentials in their own right, not LDAP passwords.
		if strings.HasPrefix(decodePassword(pass), consts.APIKeyPrefix) {
			usr, err = ds.User().FindByUsername(ctx, username)
			if err == nil {
				keyPlayer, err = playerFromPasswordKey(ctx, ds, usr, pass)
				if errors.Is(err, model.ErrInvalidAuth) {
					// Preserve legacy real passwords beginning with the key prefix.
					_, lookupErr := ds.Player().FindByAPIKey(ctx, decodePassword(pass))
					if errors.Is(lookupErr, model.ErrNotFound) {
						usr, err = server.ValidateLogin(ctx, ds.User(), username, pass)
					}
				}
			}
		} else {
			usr, err = server.ValidateLogin(ctx, ds.User(), username, pass)
		}
		if err == nil && usr == nil {
			keyUser, lookupErr := ds.User().FindByUsername(ctx, username)
			if lookupErr != nil {
				err = lookupErr
			} else {
				keyPlayer, err = playerFromPasswordKey(ctx, ds, keyUser, pass)
				if err == nil {
					usr = keyUser
				} else if errors.Is(err, model.ErrInvalidAuth) {
					err = model.ErrNotFound
				}
			}
		}
	} else {
		usr, err = ds.User().FindByUsernameWithPassword(ctx, username)
		if err == nil {
			err = validateCredentials(usr, pass, token, salt, jwt)
			if errors.Is(err, model.ErrInvalidAuth) && pass != "" && jwt == "" {
				keyPlayer, err = playerFromPasswordKey(ctx, ds, usr, pass)
			}
		}
	}
	return usr, keyPlayer, err
}

var apiKeyConflicts = []string{"u", "p", "t", "s", "jwt"}

func authenticateAPIKey(ctx context.Context, ds model.DataStore, limiter *authLimiter, r *http.Request, key string) (*model.User, *model.Player, error) {
	query := r.URL.Query()
	for _, param := range apiKeyConflicts {
		if query.Has(param) {
			log.Warn(ctx, "API: apiKey sent with other credentials", "auth", "apikey", "param", param, "remoteAddr", r.RemoteAddr)
			return nil, nil, newError(responses.ErrorMultipleAuthMechanismsProvided)
		}
	}

	// Per key, so a stale key on one device cannot lock out valid keys sharing the IP
	slot, allowed := limiter.acquire(ctx, "apikey\x00"+server.ClientIP(r)+"\x00"+key)
	if !allowed {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		log.Warn(ctx, "API: Too many failed API key attempts", "auth", "apikey", "remoteAddr", r.RemoteAddr)
		return nil, nil, newError(responses.ErrorInvalidAPIKey)
	}

	player, err := ds.Player().FindByAPIKey(ctx, key)
	var usr *model.User
	if err == nil {
		usr, err = ds.User().Get(ctx, player.UserId)
	}
	slot.release(errors.Is(err, model.ErrNotFound))
	switch {
	case errors.Is(err, context.Canceled):
		return nil, nil, err
	case errors.Is(err, model.ErrNotFound):
		log.Warn(ctx, "API: Invalid API key", "auth", "apikey", "remoteAddr", r.RemoteAddr)
		return nil, nil, newError(responses.ErrorInvalidAPIKey)
	case err != nil:
		log.Error(ctx, "API: Error authenticating API key", "auth", "apikey", "remoteAddr", r.RemoteAddr, err)
		return nil, nil, newError(responses.ErrorAuthenticationFail)
	}
	return usr, player, nil
}

// playerFromPasswordKey lets clients that only have a password field log in with an API key.
// It returns ErrInvalidAuth when pass is not a key of usr, so only real failures skip the limiter count.
func playerFromPasswordKey(ctx context.Context, ds model.DataStore, usr *model.User, pass string) (*model.Player, error) {
	key := decodePassword(pass)
	if !strings.HasPrefix(key, consts.APIKeyPrefix) {
		return nil, model.ErrInvalidAuth
	}
	plr, err := ds.Player().FindByAPIKey(ctx, key)
	if errors.Is(err, model.ErrNotFound) || (err == nil && plr.UserId != usr.ID) {
		return nil, model.ErrInvalidAuth
	}
	return plr, err
}

func decodePassword(pass string) string {
	if strings.HasPrefix(pass, "enc:") {
		if dec, err := hex.DecodeString(pass[4:]); err == nil {
			return string(dec)
		}
	}
	return pass
}

func adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loggedUser, ok := request.UserFrom(r.Context())
		if !ok {
			sendError(w, r, newError(responses.ErrorGeneric, "Internal error"))
			return
		}

		if !loggedUser.IsAdmin {
			sendError(w, r, newError(responses.ErrorAuthorizationFail))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func validateCredentials(user *model.User, pass, token, salt, jwt string) error {
	valid := false

	switch {
	case jwt != "":
		claims, err := auth.Validate(jwt)
		valid = err == nil &&
			claims.Subject == user.UserName &&
			auth.CheckClaims(claims, *user, auth.AudienceSubsonic) == nil
	case pass != "":
		// Empty stored password (LDAP users post-ClearPassword, mid-migration
		// rows, etc.) must never be a valid credential — the comparison
		// `"" == ""` would otherwise succeed.
		decoded := decodePassword(pass)
		valid = decoded != "" && user.Password != "" && decoded == user.Password
	case token != "":
		if user.Password == "" {
			break
		}
		t := fmt.Sprintf("%x", md5.Sum([]byte(user.Password+salt)))
		valid = t == token
	}

	if !valid {
		return model.ErrInvalidAuth
	}
	return nil
}

// matchAppPassword tries to authenticate the request against the user's
// active app passwords. Returns:
//   - (user, appID, true)  on a match
//   - (user, "",   false)  when the user exists but no app password matched
//     (so the caller can decide whether to fall through or reject — the
//     LDAP token-auth gate uses this case)
//   - (nil,  "",   false)  when the user doesn't exist or lookup failed
//
// `pass` MUST already be the decoded plaintext (the parent `authenticate`
// flow handles `enc:` decoding once); we do not decode again.
func matchAppPassword(ctx context.Context, ds model.DataStore, username, pass, token, salt string) (*model.User, string, bool) {
	if username == "" {
		return nil, "", false
	}
	usr, err := ds.User().FindByUsername(ctx, username)
	if err != nil {
		return nil, "", false
	}
	active, err := ds.AppPassword().FindActiveByUser(ctx, usr.ID)
	if err != nil {
		log.Warn(ctx, "API: Error loading app passwords", "username", username, err)
		return usr, "", false
	}
	for _, ap := range active {
		switch {
		case pass != "" && pass == ap.Password:
			return usr, ap.ID, true
		case token != "" && fmt.Sprintf("%x", md5.Sum([]byte(ap.Password+salt))) == token:
			return usr, ap.ID, true
		}
	}
	return usr, "", false
}

func getPlayer(players core.Players) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			userName, _ := request.UsernameFrom(ctx)
			client, _ := request.ClientFrom(ctx)
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			userAgent := canonicalUserAgent(r)

			var player *model.Player
			var trc *model.Transcoding
			var err error
			keyPlayer, boundByKey := request.PlayerFrom(ctx)
			if boundByKey {
				player, trc, err = players.Touch(ctx, keyPlayer, client, userAgent, ip)
			} else {
				player, trc, err = players.Register(ctx, playerIDFromCookie(r, userName), client, userAgent, ip)
			}
			if err != nil {
				log.Error(ctx, "Could not resolve player", "username", userName, "client", client, err)
			} else {
				ctx = request.WithPlayer(ctx, *player)
				if trc != nil {
					ctx = request.WithTranscoding(ctx, *trc)
				}
				r = r.WithContext(ctx)

				// A key already identifies the player, so the cookie would only add a second, weaker signal
				if boundByKey {
					next.ServeHTTP(w, r)
					return
				}
				cookie := &http.Cookie{ //nolint:gosec // Secure omitted: Navidrome may run over plain HTTP
					Name:     playerIDCookieName(userName),
					Value:    player.ID,
					MaxAge:   consts.CookieExpiry,
					HttpOnly: true,
					SameSite: http.SameSiteStrictMode,
					Path:     cmp.Or(conf.Server.BasePath, "/"),
				}
				http.SetCookie(w, cookie)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func canonicalUserAgent(r *http.Request) string {
	u := ua.Parse(r.Header.Get("user-agent"))
	userAgent := u.Name
	if u.OS != "" {
		userAgent = userAgent + "/" + u.OS
	}
	return userAgent
}

func playerIDFromCookie(r *http.Request, userName string) string {
	cookieName := playerIDCookieName(userName)
	var playerId string
	if c, err := r.Cookie(cookieName); err == nil {
		playerId = c.Value
		log.Trace(r, "playerId found in cookies", "playerId", playerId)
	}
	return playerId
}

func playerIDCookieName(userName string) string {
	cookieName := fmt.Sprintf("nd-player-%x", userName)
	return cookieName
}

type contextKey string

const subsonicErrorPointer contextKey = "subsonicErrorPointer"

func recordStats(metrics metrics.Metrics) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			status := int32(-1)
			contextWithStatus := context.WithValue(r.Context(), subsonicErrorPointer, &status)

			start := time.Now()
			defer func() {
				elapsed := time.Since(start).Milliseconds()

				// We want to get the client name (even if not present for certain endpoints)
				p := req.Params(r)
				client, _ := p.String("c")

				// If there is no Subsonic status (e.g., HTTP 501 not implemented), fallback to HTTP
				if status == -1 {
					status = int32(ww.Status())
				}

				shortPath := strings.Replace(r.URL.Path, ".view", "", 1)

				metrics.RecordRequest(r.Context(), shortPath, r.Method, client, status, elapsed)
			}()

			next.ServeHTTP(ww, r.WithContext(contextWithStatus))
		}
		return http.HandlerFunc(fn)
	}
}
