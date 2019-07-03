package models

import (
	"github.com/jinzhu/gorm"
	"strings"

	"github.com/18F/cf-cdn-service-broker/utils"
)

type Route struct {
	gorm.Model
	InstanceId     string `gorm:"not null;unique_index"`
	State          State  `gorm:"not null;index"`
	ChallengeJSON  []byte
	DomainExternal string
	DomainInternal string
	DistId         string
	Origin         string
	Path           string
	InsecureOrigin bool
	Certificate    Certificate
	UserData       UserData
	UserDataID     int
}

func (r *Route) GetDomains() []string {
	domains := make([]string, 0)

	for _, allegedDomain := range strings.Split(r.DomainExternal, ",") {
		if len(allegedDomain) > 0 {
			domains = append(domains, allegedDomain)
		}
	}

	return domains
}

func (r *Route) loadUser(db *gorm.DB) (utils.User, error) {
	var userData UserData
	if err := db.Model(r).Related(&userData).Error; err != nil {
		helperLogger.Session("route-load-user").Error("load-user-data", err)
		return utils.User{}, err
	}

	return LoadUser(userData)
}
