package cmd

import (
	"github.com/navidrome/navidrome/model"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("applyUserEmailChange", func() {
	It("rejects an LDAP email change without mutating the user", func() {
		user := &model.User{Email: "directory@example.com", AuthType: model.AuthTypeLDAP}

		err := applyUserEmailChange(user, "forged@example.com", false)

		Expect(err).To(MatchError("LDAP user email is managed by the directory"))
		Expect(user.Email).To(Equal("directory@example.com"))
	})

	It("allows a local email change", func() {
		user := &model.User{Email: "before@example.com"}

		err := applyUserEmailChange(user, "after@example.com", false)

		Expect(err).ToNot(HaveOccurred())
		Expect(user.Email).To(Equal("after@example.com"))
	})
})
