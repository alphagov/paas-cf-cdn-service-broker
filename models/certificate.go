package models

import (
	"github.com/jinzhu/gorm"
	"time"
)

type Certificate struct {
	gorm.Model
	RouteId     uint
	Domain      string
	CertURL     string
	Certificate []byte
	Expires     time.Time `gorm:"index"`
}
