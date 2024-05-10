package firewall

import (
	"testing"
	
	"github.com/stretchr/testify/assert"
)

func TestRole(t *testing.T) {
	t.Run(
		"equal name", func(t *testing.T) {
			r1 := Role{Name: "owner"}
			r2 := Role{Name: "owner"}
			assert.True(t, r1.Compare(r2))
		},
	)
	t.Run(
		"not equal name", func(t *testing.T) {
			r1 := Role{Name: "owner"}
			r2 := Role{Name: "admin"}
			assert.False(t, r1.Compare(r2))
		},
	)
	t.Run(
		"securables pass", func(t *testing.T) {
			r1 := Role{Name: "owner", Securables: []string{"users", "posts"}}
			r2 := Role{Name: "owner", Securables: []string{"users", "posts"}}
			assert.True(t, r1.Compare(r2))
		},
	)
	t.Run(
		"securables fail", func(t *testing.T) {
			r1 := Role{Name: "owner", Securables: []string{"users", "posts"}}
			r2 := Role{Name: "owner", Securables: []string{"users"}}
			assert.False(t, r1.Compare(r2))
		},
	)
}
