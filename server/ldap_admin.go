package server

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/model"
)

// adminCheckEnabled reports whether the operator has configured an
// LDAP-driven admin policy. When this returns false, the login flow
// and the liveness sweep leave IsAdmin alone — the value persisted in
// the user table is authoritative.
func adminCheckEnabled() bool {
	return conf.Server.LDAP.AdminGroup != "" || conf.Server.LDAP.AdminFilter != ""
}

// buildAdminFilter constructs the LDAP filter used to determine
// whether the named user is an admin. Returns "" if no admin policy is
// configured (caller must check adminCheckEnabled first). Extracted as
// a pure function so the filter shape can be unit-tested without an
// LDAP connection.
func buildAdminFilter(userName string) string {
	escaped := ldap.EscapeFilter(userName)
	if g := conf.Server.LDAP.AdminGroup; g != "" {
		userFilter := fmt.Sprintf(conf.Server.LDAP.SearchFilter, escaped)
		return "(&(memberOf=" + ldap.EscapeFilter(g) + ")" + userFilter + ")"
	}
	if af := conf.Server.LDAP.AdminFilter; af != "" {
		return fmt.Sprintf(af, escaped)
	}
	return ""
}

// ldapSearcher is the subset of *ldap.Conn used by ldapAdminCheck. Keeping
// it narrow lets tests substitute a fake without a live directory; *ldap.Conn
// satisfies it.
type ldapSearcher interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

// ldapAdminCheck searches the directory to determine whether the named
// user should be granted Navidrome admin. The bound LDAP connection l
// must already be authenticated as the service account — group-membership
// reads typically require it. Caller MUST first check adminCheckEnabled()
// and skip this call when no admin policy is set.
//
// The admin filter can match more than the identity that authenticated
// (e.g. a broad AdminFilter template), so the user's own DN is resolved
// first via the configured SearchFilter and the admin search is then
// narrowed to that exact DN with ldapAdminResultForDN. A missing user is
// not an admin; an ambiguous lookup (more than one DN for one username)
// returns an error so callers preserve the existing IsAdmin instead of
// granting admin to an unverified identity.
//
// On a transient lookup error, callers MUST preserve the existing
// IsAdmin value rather than demote — this avoids a directory hiccup
// silently locking the operator out of admin functions.
func ldapAdminCheck(l ldapSearcher, userName string) (isAdmin bool, err error) {
	filter := buildAdminFilter(userName)
	if filter == "" {
		// Caller should have checked adminCheckEnabled. Treat as no-op.
		return false, nil
	}
	userDN, err := resolveLDAPUserDN(l, userName)
	if err != nil {
		return false, err
	}
	if userDN == "" {
		// No directory entry for this username: not an admin.
		return false, nil
	}
	sr, err := l.Search(ldap.NewSearchRequest(
		conf.Server.LDAP.Base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, []string{"dn"}, nil,
	))
	if err != nil {
		return false, err
	}
	return ldapAdminResultForDN(sr, userDN)
}

// resolveLDAPUserDN looks up the single directory entry matching the
// configured SearchFilter for userName. It returns ("", nil) when the user
// is absent, and an error when the search fails or the username matches
// more than one entry — an ambiguous identity must not be reconciled.
func resolveLDAPUserDN(l ldapSearcher, userName string) (string, error) {
	sr, err := l.Search(ldap.NewSearchRequest(
		conf.Server.LDAP.Base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		presenceFilter(userName), []string{"dn"}, nil,
	))
	if err != nil {
		return "", err
	}
	switch len(sr.Entries) {
	case 0:
		return "", nil
	case 1:
		return sr.Entries[0].DN, nil
	default:
		return "", fmt.Errorf("ldap admin check: user %q matched %d directory entries", userName, len(sr.Entries))
	}
}

// ldapAdminResultForDN applies the admin search only to the exact directory
// entry that authenticated. Search filters can be broader than expected, so
// another matching DN must never grant admin to this login.
func ldapAdminResultForDN(result *ldap.SearchResult, authenticatedDN string) (bool, error) {
	want, err := ldap.ParseDN(authenticatedDN)
	if err != nil {
		return false, err
	}
	for _, entry := range result.Entries {
		got, err := ldap.ParseDN(entry.DN)
		if err != nil {
			return false, err
		}
		if want.EqualFold(got) {
			return true, nil
		}
	}
	return false, nil
}

// applyLDAPAdminResult applies the outcome of an admin-membership lookup
// to the user's IsAdmin flag. A nil result means the lookup was skipped
// (admin policy not configured) or failed transiently — in both cases
// the existing IsAdmin is preserved so a directory hiccup can't lock the
// operator out. A non-nil pointer is the authoritative result and
// overwrites IsAdmin in either direction (promote or demote).
func applyLDAPAdminResult(u *model.User, adminCheckResult *bool) {
	if adminCheckResult != nil {
		u.IsAdmin = *adminCheckResult
	}
}
