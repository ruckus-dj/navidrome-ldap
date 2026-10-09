package server

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/navidrome/navidrome/conf"
)

// ldapAdminSearcher records every search so tests can assert that an
// ambiguous or missing user short-circuits before the admin search runs.
type ldapAdminSearcher struct {
	calls    []*ldap.SearchRequest
	response func(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

func (s *ldapAdminSearcher) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	s.calls = append(s.calls, req)
	return s.response(req)
}

func withLDAPAdminConfig(t *testing.T) {
	t.Helper()
	savedBase := conf.Server.LDAP.Base
	savedSearch := conf.Server.LDAP.SearchFilter
	savedGroup := conf.Server.LDAP.AdminGroup
	savedFilter := conf.Server.LDAP.AdminFilter
	t.Cleanup(func() {
		conf.Server.LDAP.Base = savedBase
		conf.Server.LDAP.SearchFilter = savedSearch
		conf.Server.LDAP.AdminGroup = savedGroup
		conf.Server.LDAP.AdminFilter = savedFilter
	})
	conf.Server.LDAP.Base = "dc=example,dc=org"
	conf.Server.LDAP.SearchFilter = "(uid=%s)"
	conf.Server.LDAP.AdminGroup = "cn=admins,dc=example,dc=org"
	conf.Server.LDAP.AdminFilter = ""
}

func resultWithDNs(dns ...string) *ldap.SearchResult {
	sr := &ldap.SearchResult{}
	for _, dn := range dns {
		sr.Entries = append(sr.Entries, &ldap.Entry{DN: dn})
	}
	return sr
}

func TestLDAPAdminCheckMatchesOnlyAuthenticatedDN(t *testing.T) {
	withLDAPAdminConfig(t)
	const userDN = "uid=alice,ou=people,dc=example,dc=org"
	presence := presenceFilter("alice")
	admin := buildAdminFilter("alice")

	searcher := &ldapAdminSearcher{response: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		switch req.Filter {
		case presence:
			return resultWithDNs(userDN), nil
		case admin:
			// Admin filter also matches bob; alice's own DN is absent.
			return resultWithDNs("uid=bob,ou=people,dc=example,dc=org"), nil
		}
		t.Fatalf("unexpected filter %q", req.Filter)
		return nil, nil
	}}

	isAdmin, err := ldapAdminCheck(searcher, "alice")
	if err != nil {
		t.Fatalf("ldapAdminCheck error = %v, want nil", err)
	}
	if isAdmin {
		t.Fatal("ldapAdminCheck granted admin for a different DN")
	}
}

func TestLDAPAdminCheckAcceptsNormalizedAuthenticatedDN(t *testing.T) {
	withLDAPAdminConfig(t)
	presence := presenceFilter("alice")
	admin := buildAdminFilter("alice")

	searcher := &ldapAdminSearcher{response: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		switch req.Filter {
		case presence:
			return resultWithDNs("uid=alice,ou=people,dc=example,dc=org"), nil
		case admin:
			// Same entry, different letter case: must normalize equal.
			return resultWithDNs("UID=ALICE,OU=PEOPLE,DC=EXAMPLE,DC=ORG"), nil
		}
		t.Fatalf("unexpected filter %q", req.Filter)
		return nil, nil
	}}

	isAdmin, err := ldapAdminCheck(searcher, "alice")
	if err != nil {
		t.Fatalf("ldapAdminCheck error = %v, want nil", err)
	}
	if !isAdmin {
		t.Fatal("ldapAdminCheck did not grant admin for the normalized authenticated DN")
	}
}

func TestLDAPAdminCheckMissingUserIsNotAdmin(t *testing.T) {
	withLDAPAdminConfig(t)
	presence := presenceFilter("ghost")

	searcher := &ldapAdminSearcher{response: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if req.Filter != presence {
			t.Fatalf("admin search must not run for a missing user; got filter %q", req.Filter)
		}
		return resultWithDNs(), nil
	}}

	isAdmin, err := ldapAdminCheck(searcher, "ghost")
	if err != nil {
		t.Fatalf("ldapAdminCheck error = %v, want nil", err)
	}
	if isAdmin {
		t.Fatal("ldapAdminCheck granted admin to a missing user")
	}
	if len(searcher.calls) != 1 {
		t.Fatalf("search calls = %d, want 1 (presence only)", len(searcher.calls))
	}
}

func TestLDAPAdminCheckAmbiguousUserReturnsError(t *testing.T) {
	withLDAPAdminConfig(t)
	presence := presenceFilter("alice")

	searcher := &ldapAdminSearcher{response: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if req.Filter != presence {
			t.Fatalf("admin search must not run for an ambiguous user; got filter %q", req.Filter)
		}
		return resultWithDNs(
			"uid=alice,ou=people,dc=example,dc=org",
			"uid=alice,ou=contractors,dc=example,dc=org",
		), nil
	}}

	isAdmin, err := ldapAdminCheck(searcher, "alice")
	if err == nil {
		t.Fatal("ldapAdminCheck error = nil, want ambiguous-lookup error")
	}
	if isAdmin {
		t.Fatal("ldapAdminCheck granted admin for an ambiguous identity")
	}
	if len(searcher.calls) != 1 {
		t.Fatalf("search calls = %d, want 1 (presence only)", len(searcher.calls))
	}
}

func TestLDAPAdminCheckPropagatesUserSearchError(t *testing.T) {
	withLDAPAdminConfig(t)
	sentinel := errors.New("directory busy")

	searcher := &ldapAdminSearcher{response: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
		return nil, sentinel
	}}

	isAdmin, err := ldapAdminCheck(searcher, "alice")
	if !errors.Is(err, sentinel) {
		t.Fatalf("ldapAdminCheck error = %v, want %v", err, sentinel)
	}
	if isAdmin {
		t.Fatal("ldapAdminCheck granted admin despite a search error")
	}
}

func TestLDAPAdminCheckPropagatesAdminSearchError(t *testing.T) {
	withLDAPAdminConfig(t)
	presence := presenceFilter("alice")
	sentinel := errors.New("admin search failed")

	searcher := &ldapAdminSearcher{response: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
		if req.Filter == presence {
			return resultWithDNs("uid=alice,ou=people,dc=example,dc=org"), nil
		}
		return nil, sentinel
	}}

	isAdmin, err := ldapAdminCheck(searcher, "alice")
	if !errors.Is(err, sentinel) {
		t.Fatalf("ldapAdminCheck error = %v, want %v", err, sentinel)
	}
	if isAdmin {
		t.Fatal("ldapAdminCheck granted admin despite an admin search error")
	}
}
