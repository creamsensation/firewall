package firewall

import (
	"slices"
)

type Role struct {
	Name       string   `json:"name"`
	Super      bool     `json:"super"`
	Securables []string `json:"securables"`
}

func (r Role) Compare(role Role) bool {
	if r.Name != role.Name {
		return false
	}
	if r.Super {
		return true
	}
	if len(r.Securables) != len(role.Securables) {
		return false
	}
	for _, s := range r.Securables {
		if !slices.Contains(role.Securables, s) {
			return false
		}
	}
	return true
}
