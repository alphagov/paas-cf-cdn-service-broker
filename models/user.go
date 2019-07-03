package models

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"

	"github.com/jinzhu/gorm"

	"github.com/18F/cf-cdn-service-broker/utils"
)

type UserData struct {
	gorm.Model
	Email string `gorm:"not null"`
	Reg   []byte
	Key   []byte
}

func CreateUser(email string) (utils.User, error) {
	user := utils.User{Email: email}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		helperLogger.Session("create-user").Error("rsa-generate-key", err)
		return user, err
	}
	user.SetPrivateKey(key)

	return user, nil
}

func SaveUser(db *gorm.DB, user utils.User) (UserData, error) {
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

func LoadUser(userData UserData) (utils.User, error) {
	var user utils.User

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
