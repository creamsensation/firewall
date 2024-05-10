package firewall

import "regexp"

type Config interface {
}

type config struct {
	name  string
	value any
}

const (
	configEnabled  = "enabled"
	configName     = "name"
	configGroup    = "group"
	configMatcher  = "matcher"
	configPath     = "path"
	configRedirect = "redirect"
	configRole     = "role"
	configSecret   = "secret"
)

func Enabled(enabled ...bool) Config {
	value := true
	if len(enabled) > 0 {
		value = enabled[0]
	}
	return &config{
		name:  configEnabled,
		value: value,
	}
}

func Groups(groups ...string) Config {
	return &config{
		name:  configGroup,
		value: groups,
	}
}

func Name(name string) Config {
	return &config{
		name:  configName,
		value: name,
	}
}

func Matchers(matchers ...*regexp.Regexp) Config {
	return &config{
		name:  configMatcher,
		value: matchers,
	}
}

func Paths(paths ...string) Config {
	return &config{
		name:  configPath,
		value: paths,
	}
}

func Redirect(redirect string) Config {
	return &config{
		name:  configRedirect,
		value: redirect,
	}
}

func Roles(roles ...Role) Config {
	return &config{
		name:  configRole,
		value: roles,
	}
}

func Secret(secret string) Config {
	return &config{
		name:  configSecret,
		value: secret,
	}
}
