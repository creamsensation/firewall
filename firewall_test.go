package firewall

import (
	"regexp"
	"testing"
	
	"github.com/stretchr/testify/assert"
)

func TestFirewall(t *testing.T) {
	t.Run(
		"super", func(t *testing.T) {
			role := Role{Name: "owner", Super: true}
			f := New(
				Enabled(true),
				Paths("/test"),
				Roles(role),
			)
			res := f.Try(
				Attempt{
					Path: "/test",
					Role: role,
				},
			)
			assert.True(t, res.Ok)
		},
	)
	t.Run(
		"secret", func(t *testing.T) {
			secret := "123456789"
			f := New(
				Enabled(true),
				Paths("/cron"),
				Secret(secret),
			)
			res := f.Try(
				Attempt{
					Path:   "/cron",
					Secret: secret,
				},
			)
			assert.True(t, res.Ok)
		},
	)
	t.Run(
		"valid securables", func(t *testing.T) {
			roleOwner := Role{Name: "owner", Securables: []string{"users-read", "users-write"}}
			f := New(
				Enabled(true),
				Paths("/users"),
				Roles(roleOwner),
			)
			res := f.Try(
				Attempt{
					Path: "/users",
					Role: roleOwner,
				},
			)
			assert.True(t, res.Ok)
		},
	)
	t.Run(
		"invalid securables", func(t *testing.T) {
			roleOwner := Role{Name: "owner", Securables: []string{"users-read", "users-write"}}
			roleAdmin := Role{Name: "admin", Securables: []string{"users-read"}}
			f := New(
				Enabled(true),
				Paths("/users"),
				Roles(roleOwner),
			)
			res := f.Try(
				Attempt{
					Path: "/users",
					Role: roleAdmin,
				},
			)
			assert.False(t, res.Ok)
		},
	)
	t.Run(
		"groups", func(t *testing.T) {
			group := "prefix"
			redirect := "/test"
			f := New(
				Enabled(true),
				Paths("/prefix/path"),
				Redirect(redirect),
				Groups(group),
			)
			res := f.Try(
				Attempt{
					Path:  "/prefix/path",
					Group: group,
				},
			)
			assert.False(t, res.Ok)
			assert.Equal(t, redirect, res.Redirect)
		},
	)
	t.Run(
		"paths", func(t *testing.T) {
			redirect := "/test"
			f := New(
				Enabled(true),
				Paths("/prefix/path"),
				Redirect(redirect),
			)
			res := f.Try(
				Attempt{
					Path: "/prefix/path",
				},
			)
			assert.False(t, res.Ok)
			assert.Equal(t, redirect, res.Redirect)
		},
	)
	t.Run(
		"matchers", func(t *testing.T) {
			redirect := "/test"
			f := New(
				Enabled(true),
				Matchers(regexp.MustCompile("^/prefix/path$")),
				Redirect(redirect),
			)
			res := f.Try(
				Attempt{
					Path: "/prefix/path",
				},
			)
			assert.False(t, res.Ok)
			assert.Equal(t, redirect, res.Redirect)
		},
	)
}
