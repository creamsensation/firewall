package firewall

import (
	"regexp"
	"slices"
)

type Firewall struct {
	Enabled  bool
	Name     string
	Groups   []string
	Matchers []*regexp.Regexp
	Paths    []string
	Redirect string
	Roles    []Role
	Secret   string
}

type Attempt struct {
	Group  string
	Path   string
	Role   Role
	Secret string
}

type Result struct {
	Ok       bool
	Err      error
	Redirect string
}

func New(configs ...Config) *Firewall {
	f := &Firewall{
		Groups:   make([]string, 0),
		Matchers: make([]*regexp.Regexp, 0),
		Paths:    make([]string, 0),
		Roles:    make([]Role, 0),
	}
	for _, item := range configs {
		c, ok := item.(*config)
		if !ok {
			continue
		}
		switch c.name {
		case configEnabled:
			f.Enabled = c.value.(bool)
		case configName:
			f.Name = c.value.(string)
		case configGroup:
			f.Groups = append(f.Groups, c.value.([]string)...)
		case configMatcher:
			f.Matchers = append(f.Matchers, c.value.([]*regexp.Regexp)...)
		case configPath:
			f.Paths = append(f.Paths, c.value.([]string)...)
		case configRedirect:
			f.Redirect = c.value.(string)
		case configRole:
			f.Roles = append(f.Roles, c.value.([]Role)...)
		case configSecret:
			f.Secret = c.value.(string)
		}
	}
	return f
}

func (f *Firewall) Try(attempt Attempt) Result {
	if !f.Enabled {
		return Result{Ok: true}
	}
	if len(f.Secret) > 0 && f.Secret == attempt.Secret {
		return Result{Ok: true}
	}
	if len(f.Roles) > 0 {
		for _, r := range f.Roles {
			if r.Compare(attempt.Role) {
				return Result{Ok: true}
			}
		}
	}
	if len(f.Groups) > 0 && slices.Contains(f.Groups, attempt.Group) {
		return Result{Redirect: f.Redirect}
	}
	if len(f.Paths) > 0 && slices.Contains(f.Paths, attempt.Path) {
		return Result{Redirect: f.Redirect}
	}
	if len(f.Matchers) > 0 {
		for _, m := range f.Matchers {
			if m.MatchString(attempt.Path) {
				return Result{Redirect: f.Redirect}
			}
		}
	}
	return Result{Ok: true}
}
