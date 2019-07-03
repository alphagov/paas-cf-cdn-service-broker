package models

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"

	"github.com/jinzhu/gorm"
	"github.com/xenolf/lego/acme"
)

type User struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func (u *User) SetPrivateKey(key crypto.PrivateKey) {
	u.key = key
}

type UserData struct {
	gorm.Model
	Email string `gorm:"not null"`
	Reg   []byte
	Key   []byte
}

func CreateUser(email string) (User, error) {
	user := User{Email: email}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		helperLogger.Session("create-user").Error("rsa-generate-key", err)
		return user, err
	}
	user.SetPrivateKey(key)

	return user, nil
}

func SaveUser(db *gorm.DB, user User) (UserData, error) {
	var err error
	userData := UserData{Email: user.GetEmail()}

	lsession := helperLogger.Session("save-user")

	userData.Key, err = savePrivateKey(user.GetPrivateKey())
	if err != nil {
		lsession.Error("save-private-key", err)
		return userData, err
	}
	userData.Reg, err = json.Marshal(user)
	if err != nil {
		lsession.Error("json-marshal-user", err)
		return userData, err
	}

	if err := db.Save(&userData).Error; err != nil {
		lsession.Error("db-save-user", err)
		return userData, err
	}

	return userData, nil
}

func LoadUser(userData UserData) (User, error) {
	var user User

	lsession := helperLogger.Session("load-user")

	if err := json.Unmarshal(userData.Reg, &user); err != nil {
		lsession.Error("json-unmarshal-user-data", err)
		return user, err
	}
	key, err := loadPrivateKey(userData.Key)
	if err != nil {
		lsession.Error("load-private-key", err)
		return user, err
	}
	user.SetPrivateKey(key)
	return user, nil
}
