// Package auth provides multi-credential SOCKS5 authentication.
//
// Supports multiple username/password pairs, including the same username
// with different passwords:
//
//	a := auth.New(
//	    auth.Credential("user1", "pass1"),
//	    auth.Credential("user1", "pass2"),
//	    auth.Credential("admin", "secret"),
//	)
//	a.Authenticate("user1", "pass2") // true
package auth

// CredentialEntry holds a username/password pair.
type CredentialEntry struct {
	Username string
	Password string
}

// Credential creates a CredentialEntry.
func Credential(username, password string) CredentialEntry {
	return CredentialEntry{Username: username, Password: password}
}

// Multi stores multiple credential pairs.
// The same username can have different passwords.
type Multi struct {
	// map[username]map[password]struct{} for O(1) lookup.
	creds map[string]map[string]struct{}
}

// New creates a Multi authenticator from credential entries.
func New(entries ...CredentialEntry) *Multi {
	m := &Multi{
		creds: make(map[string]map[string]struct{}),
	}
	for _, e := range entries {
		if _, ok := m.creds[e.Username]; !ok {
			m.creds[e.Username] = make(map[string]struct{})
		}
		m.creds[e.Username][e.Password] = struct{}{}
	}
	return m
}

// Authenticate checks if the username/password combination is valid.
func (m *Multi) Authenticate(username, password string) bool {
	if passwords, ok := m.creds[username]; ok {
		_, valid := passwords[password]
		return valid
	}
	return false
}

// Count returns the total number of credential entries.
func (m *Multi) Count() int {
	total := 0
	for _, passwords := range m.creds {
		total += len(passwords)
	}
	return total
}

// Users returns the list of unique usernames.
func (m *Multi) Users() []string {
	users := make([]string, 0, len(m.creds))
	for u := range m.creds {
		users = append(users, u)
	}
	return users
}
