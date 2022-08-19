package matcher_test

import (
	_ "embed"
	"encoding/json"

	"github.com/mimuret/dnsutils/matcher"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Config", func() {
	Context("UnmarshalJSON", func() {
		var (
			mc  *matcher.MatcherConfig
			err error
		)
		BeforeEach(func() {
			mc = &matcher.MatcherConfig{}
		})
		When("invalid json string", func() {
			BeforeEach(func() {
				err = json.Unmarshal([]byte(`{"Type":1}`), mc)
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("Type is invalid", func() {
			BeforeEach(func() {
				err = json.Unmarshal([]byte(`{"Type":"","Name":"Static","Arg":true}`), mc)
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("Name is invalid", func() {
			BeforeEach(func() {
				err = json.Unmarshal([]byte(`{"Type":"DNS","Name":"Dummy","Arg":true}`), mc)
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("Arg is invalid", func() {
			BeforeEach(func() {
				err = json.Unmarshal([]byte(`{"Type":"DNS","Name":"Static","Arg":1}`), mc)
			})
			It("returns error", func() {
				Expect(err).To(HaveOccurred())
			})
		})
		When("valid data", func() {
			BeforeEach(func() {
				err = json.Unmarshal([]byte(`{"Type":"DNS","Name":"Static","Arg":true}`), mc)
			})
			It("returns error", func() {
				Expect(err).To(Succeed())
				Expect(mc).To(Equal(&matcher.MatcherConfig{Type: matcher.MatcherTypeDnsMsg, Name: "Static", Arg: true}))
			})
		})
	})
})
