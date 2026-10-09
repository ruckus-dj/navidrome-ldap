package subsonic

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/request"
	"github.com/navidrome/navidrome/tests"
	ber "gopkg.in/asn1-ber.v1"
)

// servePasswordLDAP exercises the real LDAP client with a minimal directory:
// service bind, user search, and a user bind that checks the submitted password.
func servePasswordLDAP(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var binds atomic.Int32
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				write := func(id int64, op *ber.Packet) {
					packet := ber.NewSequence("LDAP message")
					packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "ID"))
					packet.AppendChild(op)
					_, _ = conn.Write(packet.Bytes())
				}
				result := func(id int64, tag ber.Tag, code int) {
					op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "Result")
					op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "Code"))
					op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "DN"))
					op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Message"))
					write(id, op)
				}
				for {
					packet, err := ber.ReadPacket(conn)
					if err != nil {
						return
					}
					id := packet.Children[0].Value.(int64)
					op := packet.Children[1]
					switch op.Tag {
					case ldap.ApplicationBindRequest:
						binds.Add(1)
						dn := op.Children[1].Value.(string)
						password := string(op.Children[2].Data.Bytes())
						code := ldap.LDAPResultInvalidCredentials
						if (dn == "cn=service" && password == "service-secret") ||
							(dn == "uid=ldapper,dc=test" && password == "directory-secret") {
							code = ldap.LDAPResultSuccess
						}
						result(id, ldap.ApplicationBindResponse, code)
					case ldap.ApplicationSearchRequest:
						entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "Entry")
						entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=ldapper,dc=test", "DN"))
						entry.AppendChild(ber.NewSequence("Attributes"))
						write(id, entry)
						result(id, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess)
					default:
						return
					}
				}
			}()
		}
	}()
	return "ldap://" + listener.Addr().String(), &binds
}

func TestLDAPLegacyPasswordAuth(t *testing.T) {
	saved := conf.Server.LDAP
	t.Cleanup(func() { conf.Server.LDAP = saved })
	host, binds := servePasswordLDAP(t)
	conf.Server.LDAP.Host = host
	conf.Server.LDAP.BindDN = "cn=service"
	conf.Server.LDAP.BindPassword = "service-secret"
	conf.Server.LDAP.Base = "dc=test"
	conf.Server.LDAP.SearchFilter = "(uid=%s)"
	conf.Server.LDAP.AdminGroup = ""
	conf.Server.LDAP.AdminFilter = ""

	token := func(password string) string {
		return fmt.Sprintf("t=%x", md5.Sum([]byte(password+"salt")))
	}
	for _, tc := range []struct {
		name     string
		params   []string
		accepted bool
		binds    int32
		newUser  bool
	}{
		{"directory password", []string{"p=directory-secret"}, true, 2, false},
		{"encoded directory password", []string{fmt.Sprintf("p=enc:%x", []byte("directory-secret"))}, true, 2, false},
		{"first directory login", []string{"p=directory-secret"}, true, 2, true},
		{"wrong directory password", []string{"p=wrong"}, false, 2, false},
		{"empty password", []string{"p="}, false, 0, false},
		{"empty encoded password", []string{"p=enc:"}, false, 0, false},
		{"directory token", []string{token("directory-secret"), "s=salt"}, false, 0, false},
		{"app password skips LDAP", []string{"p=app-secret"}, true, 0, false},
		{"encoded app password skips LDAP", []string{fmt.Sprintf("p=enc:%x", []byte("app-secret"))}, true, 0, false},
		{"app token skips LDAP", []string{token("app-secret"), "s=salt"}, true, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ds := &tests.MockDataStore{}
			if !tc.newUser {
				if err := ds.User().Put(context.Background(), &model.User{
					ID: "ldap-id", UserName: "ldapper", AuthType: model.AuthTypeLDAP,
				}); err != nil {
					t.Fatal(err)
				}
				if err := ds.AppPassword().Put(context.Background(), &model.AppPassword{
					UserID: "ldap-id", Name: "client", NewPassword: "app-secret",
				}); err != nil {
					t.Fatal(err)
				}
			}
			before := binds.Load()
			w := httptest.NewRecorder()
			next := &mockHandler{}
			authenticate(ds)(next).ServeHTTP(w, newGetRequest(append([]string{"u=ldapper"}, tc.params...)...))
			if next.called != tc.accepted {
				t.Fatalf("accepted=%v, expected %v: %s", next.called, tc.accepted, w.Body.String())
			}
			if tc.accepted {
				user, _ := request.UserFrom(next.req.Context())
				if !user.IsLDAP() || user.UserName != "ldapper" || user.Password != "" {
					t.Fatal("expected authenticated LDAP user without a stored password")
				}
				stored, err := ds.User().FindByUsernameWithPassword(context.Background(), "ldapper")
				if err != nil || stored.Password != "" || stored.NewPassword != "" {
					t.Fatal("directory password must not be persisted")
				}
			} else if !strings.Contains(w.Body.String(), `code="40"`) {
				t.Fatalf("expected authentication failure: %s", w.Body.String())
			}
			if got := binds.Load() - before; got != tc.binds {
				t.Fatalf("expected %d LDAP binds, got %d", tc.binds, got)
			}
		})
	}
}

func TestPasswordFieldAPIKeySkipsLDAPAndIsBoundToNamedUser(t *testing.T) {
	saved := conf.Server.LDAP
	t.Cleanup(func() { conf.Server.LDAP = saved })
	host, binds := servePasswordLDAP(t)
	conf.Server.LDAP.Host = host
	conf.Server.LDAP.BindDN = "cn=service"
	conf.Server.LDAP.BindPassword = "service-secret"
	conf.Server.LDAP.Base = "dc=test"
	conf.Server.LDAP.SearchFilter = "(uid=%s)"
	conf.Server.LDAP.AdminGroup = ""
	conf.Server.LDAP.AdminFilter = ""

	key := "nds_0123456789012345678901"
	for _, tc := range []struct {
		name     string
		username string
		accepted bool
	}{
		{name: "matching user", username: "ldapper", accepted: true},
		{name: "wrong user", username: "other", accepted: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ds := &tests.MockDataStore{}
			for _, user := range []model.User{
				{ID: "ldap-id", UserName: "ldapper", AuthType: model.AuthTypeLDAP},
				{ID: "other-id", UserName: "other", AuthType: model.AuthTypeLDAP},
			} {
				if err := ds.User().Put(context.Background(), &user); err != nil {
					t.Fatal(err)
				}
			}
			if err := ds.Player().Put(context.Background(), &model.Player{ID: "key-player", UserId: "ldap-id"}); err != nil {
				t.Fatal(err)
			}
			if err := ds.Player().SetAPIKey(context.Background(), "key-player", key); err != nil {
				t.Fatal(err)
			}

			before := binds.Load()
			w := httptest.NewRecorder()
			next := &mockHandler{}
			authenticate(ds)(next).ServeHTTP(w, newGetRequest("u="+tc.username, "p="+key))
			if next.called != tc.accepted {
				t.Fatalf("accepted=%v, expected %v: %s", next.called, tc.accepted, w.Body.String())
			}
			if got := binds.Load() - before; got != 0 {
				t.Fatalf("API key auth must not bind to LDAP; got %d binds", got)
			}
		})
	}
}
