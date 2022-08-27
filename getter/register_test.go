package getter_test

import (
	"github.com/mimuret/dnsutils/getter"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("register", func() {
	Context("RegisterDnstapGetFunc", func() {
		When("name is empty", func() {
			It("raise panic", func() {
				Expect(func() {
					getter.RegisterDnstapGetFunc("", getter.GetMessageType, getter.GetMessageTypeString)
				}).To(Panic())
			})
		})
		When("getFunc is nil", func() {
			It("raise panic", func() {
				Expect(func() {
					getter.RegisterDnstapGetFunc("test", nil, getter.GetMessageTypeString)
				}).To(Panic())
			})
		})
		When("getFunc is nilValue", func() {
			It("raise panic", func() {
				var getFunc getter.DnstapGetFunc
				Expect(func() {
					getter.RegisterDnstapGetFunc("test", getFunc, getter.GetMessageTypeString)
				}).To(Panic())
			})
		})
		When("strFunc is nil", func() {
			It("raise panic", func() {
				Expect(func() {
					getter.RegisterDnstapGetFunc("test", getter.GetMessageType, nil)
				}).To(Panic())
			})
		})
		When("strFunc is nilValue", func() {
			It("raise panic", func() {
				var strFunc getter.DnstapStrFunc
				Expect(func() {
					getter.RegisterDnstapGetFunc("", getter.GetMessageType, strFunc)
				}).To(Panic())
			})
		})
		When("vaild args", func() {
			It("no raise panic", func() {
				Expect(func() {
					getter.RegisterDnstapGetFunc("test", getter.GetMessageType, getter.GetMessageTypeString)
				}).NotTo(Panic())
			})
		})
	})
	Context("RegisterDnsMsgGetFunc", func() {
		When("name is empty", func() {
			It("raise panic", func() {
				Expect(func() {
					getter.RegisterDnsMsgGetFunc("", getter.GetAuthenticatedData, getter.GetAuthenticatedDataString)
				}).To(Panic())
			})
		})
		When("getFunc is nil", func() {
			It("raise panic", func() {
				Expect(func() {
					getter.RegisterDnsMsgGetFunc("test", nil, getter.GetAuthenticatedDataString)
				}).To(Panic())
			})
		})
		When("getFunc is nilValue", func() {
			It("raise panic", func() {
				var getFunc getter.DnsMsgGetFunc
				Expect(func() {
					getter.RegisterDnsMsgGetFunc("test", getFunc, getter.GetAuthenticatedDataString)
				}).To(Panic())
			})
		})
		When("strFunc is nil", func() {
			It("raise panic", func() {
				Expect(func() {
					getter.RegisterDnsMsgGetFunc("test", getter.GetAuthenticatedData, nil)
				}).To(Panic())
			})
		})
		When("strFunc is nilValue", func() {
			It("raise panic", func() {
				var strFunc getter.DnsMsgStrFunc
				Expect(func() {
					getter.RegisterDnsMsgGetFunc("", getter.GetAuthenticatedData, strFunc)
				}).To(Panic())
			})
		})
		When("vaild args", func() {
			It("no raise panic", func() {
				Expect(func() {
					getter.RegisterDnsMsgGetFunc("test", getter.GetAuthenticatedData, getter.GetAuthenticatedDataString)
				}).NotTo(Panic())
			})
		})
	})
})
