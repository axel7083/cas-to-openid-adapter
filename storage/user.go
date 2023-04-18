package storage

import (
	"crypto/rsa"
	"golang.org/x/text/language"
)

type User struct {
	ID                string
	Username          string
	Password          string
	FirstName         string
	LastName          string
	Email             string
	EmailVerified     bool
	Phone             string
	PhoneVerified     bool
	PreferredLanguage language.Tag
	IsAdmin           bool
	Groups            []string
}

type Service struct {
	keys map[string]*rsa.PublicKey
}

type UserStore interface {
	GetUserByID(string) *User
	ExampleClientID() string
	AppendUser(user *User)
}

type userStore struct {
	users map[string]*User
}

func NewUserStore() UserStore {
	return userStore{
		users: map[string]*User{},
	}
}

// ExampleClientID is only used in the example server
func (u userStore) ExampleClientID() string {
	return "service"
}

func (u userStore) GetUserByID(id string) *User {
	return u.users[id]
}

func (u userStore) AppendUser(user *User) {
	u.users[user.ID] = user
}
