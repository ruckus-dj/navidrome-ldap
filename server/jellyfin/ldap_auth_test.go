package jellyfin

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/server/jellyfin/dto"
	"github.com/navidrome/navidrome/tests"
	"github.com/stretchr/testify/require"
	ber "gopkg.in/asn1-ber.v1"
)

func TestAuthenticateByName_authenticatesLDAPCredentials(t *testing.T) {
	// Given
	savedLDAP := conf.Server.LDAP
	t.Cleanup(func() { conf.Server.LDAP = savedLDAP })
	host, binds := serveJellyfinPasswordLDAP(t)
	conf.Server.LDAP.Host = host
	conf.Server.LDAP.BindDN = "cn=service"
	conf.Server.LDAP.BindPassword = "service-secret"
	conf.Server.LDAP.Base = "dc=test"
	conf.Server.LDAP.SearchFilter = "(uid=%s)"
	conf.Server.LDAP.AdminGroup = ""
	conf.Server.LDAP.AdminFilter = ""

	ds := &tests.MockDataStore{}
	auth.Init(ds)
	api := &Router{ds: ds}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/Users/AuthenticateByName", strings.NewReader(`{"Username":"ldapper","Pw":"directory-secret"}`))

	// When
	api.routes().ServeHTTP(w, r)

	// Then
	require.Equal(t, http.StatusOK, w.Code)
	var result dto.AuthenticationResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	require.Equal(t, "ldapper", result.User.Name)
	require.NotEmpty(t, result.AccessToken)
	require.Equal(t, int32(2), binds.Load())

	user, err := ds.User(context.Background()).FindByUsernameWithPassword("ldapper")
	require.NoError(t, err)
	require.True(t, user.IsLDAP())
	require.Empty(t, user.Password)
}

func serveJellyfinPasswordLDAP(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var binds atomic.Int32
	done := make(chan struct{})
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
		<-done
	})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
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
					packet, readErr := ber.ReadPacket(conn)
					if readErr != nil {
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
						if (dn == "cn=service" && password == "service-secret") || (dn == "uid=ldapper,dc=test" && password == "directory-secret") {
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
