package models

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql/driver"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"time"

	"code.cloudfoundry.org/lager"
	"github.com/18F/cf-cdn-service-broker/lego/acme"
	"github.com/jinzhu/gorm"
	"github.com/pivotal-cf/brokerapi"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudfront"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/18F/cf-cdn-service-broker/config"
	"github.com/18F/cf-cdn-service-broker/utils"
)

type State string

const (
	Provisioning   State = "provisioning"
	Provisioned          = "provisioned"
	Deprovisioning       = "deprovisioning"
	Deprovisioned        = "deprovisioned"
)

var (
	helperLogger = lager.NewLogger("helper-logger")
)

// Marshal a `State` to a `string` when saving to the database
func (s State) Value() (driver.Value, error) {
	return string(s), nil
}

// Unmarshal an `interface{}` to a `State` when reading from the database
func (s *State) Scan(value interface{}) error {
	switch value.(type) {
	case string:
		*s = State(value.(string))
	case []byte:
		*s = State(value.([]byte))
	default:
		err := fmt.Errorf("%s-is-incompatible", value)
		helperLogger.Session("state-scan").Error("scan-switch", err)
		return err
	}
	return nil
}

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

func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(&Route{}, &Certificate{}, &UserData{}).Error; err != nil {
		return err
	}
	db.Model(&UserData{}).RemoveIndex("uix_user_data_email")
	return nil
}

// loadPrivateKey loads a PEM-encoded ECC/RSA private key from an array of bytes.
func loadPrivateKey(keyBytes []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}

// savePrivateKey saves a PEM-encoded ECC/RSA private key to an array of bytes.
func savePrivateKey(key crypto.PrivateKey) ([]byte, error) {
	var pemType string
	var keyBytes []byte
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		var err error
		pemType = "EC"
		keyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			helperLogger.Session("save-private-key").Error("marshal-ec-private-key", err)
			return nil, err
		}
	case *rsa.PrivateKey:
		pemType = "RSA"
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	}

	pemKey := pem.Block{Type: pemType + " PRIVATE KEY", Bytes: keyBytes}
	return pem.EncodeToMemory(&pemKey), nil
}

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
	return strings.Split(r.DomainExternal, ",")
}

func (r *Route) loadUser(db *gorm.DB) (utils.User, error) {
	var userData UserData
	if err := db.Model(r).Related(&userData).Error; err != nil {
		helperLogger.Session("route-load-user").Error("load-user-data", err)
		return utils.User{}, err
	}

	return LoadUser(userData)
}

type Certificate struct {
	gorm.Model
	RouteId     uint
	Domain      string
	CertURL     string
	Certificate []byte
	Expires     time.Time `gorm:"index"`
}

type RouteManagerIface interface {
	Create(instanceId, domain, origin, path string, insecureOrigin bool, forwardedHeaders utils.Headers, forwardCookies bool, tags map[string]string) (*Route, error)
	Update(instanceId string, domain, origin string, path string, insecureOrigin bool, forwardedHeaders utils.Headers, forwardCookies bool) error
	Get(instanceId string) (*Route, error)
	Poll(route *Route) error
	Disable(route *Route) error
	Renew(route *Route) error
	RenewAll()
	DeleteOrphanedCerts()
	GetDNSInstructions(route *Route) ([]string, error)
}

type RouteManager struct {
	logger             lager.Logger
	iam                utils.IamIface
	cloudFront         utils.DistributionIface
	settings           config.Settings
	db                 *gorm.DB
	acmeClientProvider AcmeClientProviderInterface
}

func NewManager(
	logger lager.Logger,
	iam utils.IamIface,
	cloudFront utils.DistributionIface,
	settings config.Settings,
	db *gorm.DB,
	acmeClientProvider AcmeClientProviderInterface,
) RouteManager {
	return RouteManager{
		logger:             logger,
		iam:                iam,
		cloudFront:         cloudFront,
		settings:           settings,
		db:                 db,
		acmeClientProvider: acmeClientProvider,
	}
}

func (m *RouteManager) Create(instanceId, domain, origin, path string, insecureOrigin bool, forwardedHeaders utils.Headers, forwardCookies bool, tags map[string]string) (*Route, error) {
	route := &Route{
		InstanceId:     instanceId,
		State:          Provisioning,
		DomainExternal: domain,
		Origin:         origin,
		Path:           path,
		InsecureOrigin: insecureOrigin,
	}

	lsession := m.logger.Session("route-manager-create-route", lager.Data{
		"instance-id": instanceId,
	})

	user, err := CreateUser(m.settings.Email)
	if err != nil {
		lsession.Error("create-user", err)
		return nil, err
	}

	client, err := m.getDNS01Client(&user, m.settings)
	if err != nil {
		lsession.Error("get-dns-01-client", err)
		return nil, err
	}

	userData, err := SaveUser(m.db, user)
	if err != nil {
		lsession.Error("save-user", err)
		return nil, err
	}

	route.UserData = userData

	if err := m.ensureChallenges(route, client); err != nil {
		lsession.Error("ensure-challenges-dns-01", err)
		return nil, err
	}

	dist, err := m.cloudFront.Create(instanceId, make([]string, 0), origin, path, insecureOrigin, forwardedHeaders, forwardCookies, tags)
	if err != nil {
		lsession.Error("create-cloudfront-instance", err)
		return nil, err
	}

	route.DomainInternal = *dist.DomainName
	route.DistId = *dist.Id

	if err := m.db.Create(route).Error; err != nil {
		lsession.Error("db-create-route", err)
		return nil, err
	}

	return route, nil
}

func (m *RouteManager) Get(instanceId string) (*Route, error) {
	route := Route{}

	lsession := m.logger.Session("route-manager-get")

	result := m.db.First(&route, Route{InstanceId: instanceId})
	if result.Error == nil {
		lsession.Error("db-get-first-route", result.Error)
		return &route, nil
	} else if result.RecordNotFound() {
		lsession.Error("db-record-not-found", brokerapi.ErrInstanceDoesNotExist)
		return nil, brokerapi.ErrInstanceDoesNotExist
	} else {
		lsession.Error("db-generic-error", result.Error)
		return nil, result.Error
	}
}

func (m *RouteManager) Update(instanceId, domain, origin string, path string, insecureOrigin bool, forwardedHeaders utils.Headers, forwardCookies bool) error {
	lsession := m.logger.Session("route-manager-update", lager.Data{
		"instance-id": instanceId,
	})

	// Get current route
	route, err := m.Get(instanceId)
	if err != nil {
		lsession.Error("get-route", err)
		return err
	}

	// When we update the CloudFront distribution we should use the old domains
	// until we have a valid certificate in IAM.
	// CloudFront gets updated when we receive new certificates during Poll
	oldDomainsForCloudFront := route.GetDomains()

	// Override any settings that are new or different.
	if domain != "" {
		route.DomainExternal = domain
	}
	if origin != "" {
		route.Origin = origin
	}
	if path != route.Path {
		route.Path = path
	}
	if insecureOrigin != route.InsecureOrigin {
		route.InsecureOrigin = insecureOrigin
	}

	// Update the distribution
	dist, err := m.cloudFront.Update(route.DistId, oldDomainsForCloudFront,
		route.Origin, route.Path, route.InsecureOrigin, forwardedHeaders, forwardCookies)
	if err != nil {
		lsession.Error("cloudfront-update", err)
		return err
	}
	route.State = Provisioning

	// Get the updated domain name and dist id.
	route.DomainInternal = *dist.DomainName
	route.DistId = *dist.Id

	if domain != "" {
		// We need to ensure there is a challenge in the database when provisioning
		// It does not matter which client HTTP01 or DNS01 we use because it is the
		// responsibility of the ACME server to give us what challenges are
		// supported. I.e. LetsEncrypt will return ALPN01, HTTP01, DNS01 regardless
		// of which client is used
		user, err := route.loadUser(m.db)
		if err != nil {
			lsession.Error("load-user", err)
			return err
		}

		client, err := m.getHTTP01Client(&user, m.settings)
		if err != nil {
			lsession.Error("get-clients", err)
			return err
		}

		route.ChallengeJSON = []byte("")
		if err := m.ensureChallenges(route, client); err != nil {
			lsession.Error("ensure-challenges", err)
			return err
		}
	}

	// Save the database.
	result := m.db.Save(route)
	if result.Error != nil {
		lsession.Error("db-save-route", err)
		return result.Error
	}
	return nil
}

func (m *RouteManager) Poll(r *Route) error {
	switch r.State {
	case Provisioning:
		return m.updateProvisioning(r)
	case Deprovisioning:
		return m.updateDeprovisioning(r)
	default:
		return nil
	}
}

func (m *RouteManager) Disable(r *Route) error {
	lsession := m.logger.Session("route-manager-disable", lager.Data{
		"instance-id": r.InstanceId,
	})

	err := m.cloudFront.Disable(r.DistId)
	if err != nil {
		lsession.Error("cloudfront-disable", err)
		return err
	}

	r.State = Deprovisioning
	if err := m.db.Save(r).Error; err != nil {
		lsession.Error("db-save-error", err)
	}

	return nil
}

func (m *RouteManager) stillActive(r *Route) error {

	m.logger.Info("Starting canary check", lager.Data{
		"route": r,
	})

	lsession := m.logger.Session("route-manager-still-active", lager.Data{
		"instance-id": r.InstanceId,
	})

	lsession.Info("starting-canary-check", lager.Data{
		"route":       r,
		"settings":    m.settings,
		"instance-id": r.InstanceId,
	})

	session := session.New(aws.NewConfig().WithRegion(m.settings.AwsDefaultRegion))

	s3client := s3.New(session)

	target := path.Join(".well-known", "acme-challenge", "canary", r.InstanceId)

	input := s3.PutObjectInput{
		Bucket: aws.String(m.settings.Bucket),
		Key:    aws.String(target),
		Body:   strings.NewReader(r.InstanceId),
	}

	if m.settings.ServerSideEncryption != "" {
		input.ServerSideEncryption = aws.String(m.settings.ServerSideEncryption)
	}

	if _, err := s3client.PutObject(&input); err != nil {
		lsession.Error("s3-put-object", err)
		return err
	}

	insecureClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, domain := range r.GetDomains() {
		resp, err := insecureClient.Get("https://" + path.Join(domain, target))
		if err != nil {
			lsession.Error("insecure-client-get", err)
			return err
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			lsession.Error("read-response-body", err)
			return err
		}

		if string(body) != r.InstanceId {
			err := fmt.Errorf("Canary check failed for %s; expected %s, got %s", domain, r.InstanceId, string(body))
			lsession.Error("", err)
			return err
		}
	}

	return nil
}

func (m *RouteManager) Renew(r *Route) error {
	lsession := m.logger.Session("route-manager-renew", lager.Data{
		"instance-id": r.InstanceId,
	})

	err := m.stillActive(r)
	if err != nil {
		err := fmt.Errorf("Route is not active, skipping renewal: %v", err)
		lsession.Error("still-active", err)
		return err
	}

	var certRow Certificate
	err = m.db.Model(r).Related(&certRow, "Certificate").Error
	if err != nil {
		lsession.Error("db-find-related-cert", err)
		return err
	}

	user, err := r.loadUser(m.db)
	if err != nil {
		lsession.Error("db-load-user", err)
		return err
	}

	client, err := m.getHTTP01Client(&user, m.settings)
	if err != nil {
		lsession.Error("get-http01-client", err)
		return err
	}

	certResource, errs := client.ObtainCertificate(r.GetDomains(), true, nil, false)
	if len(errs) > 0 {
		err := fmt.Errorf("Error(s) obtaining certificate: %v", errs)
		lsession.Error("obtain-certificate", err)
		return err
	}

	expires, err := acme.GetPEMCertExpiration(certResource.Certificate)
	if err != nil {
		lsession.Error("get-pem-cert-expiry", err)
		return err
	}

	if err := m.deployCertificate(*r, certResource); err != nil {
		lsession.Error("deploy-certificate", err)
		return err
	}

	certRow.Domain = certResource.Domain
	certRow.CertURL = certResource.CertURL
	certRow.Certificate = certResource.Certificate
	certRow.Expires = expires
	if err := m.db.Save(&certRow).Error; err != nil {
		lsession.Error("db-save-cert", err)
		return err
	}
	return nil
}

func (m *RouteManager) DeleteOrphanedCerts() {
	// iterate over all distributions and record all certificates in-use by these distributions
	activeCerts := make(map[string]string)

	err := m.cloudFront.ListDistributions(func(distro cloudfront.DistributionSummary) bool {
		if distro.ViewerCertificate.IAMCertificateId != nil {
			activeCerts[*distro.ViewerCertificate.IAMCertificateId] = *distro.ARN
		}
		return true
	})

	if err != nil {
		m.logger.Error("cloudfront_list_distributions", err)
		return
	}

	// iterate over all certificates
	err = m.iam.ListCertificates(func(cert iam.ServerCertificateMetadata) bool {

		// delete any certs not attached to a distribution that are older than 24 hours
		_, active := activeCerts[*cert.ServerCertificateId]
		if !active && time.Since(*cert.UploadDate).Hours() > 24 {
			m.logger.Info("cleaning-orphaned-certificate", lager.Data{
				"cert": cert,
			})

			err := m.iam.DeleteCertificate(*cert.ServerCertificateName)
			if err != nil {
				m.logger.Error("iam-delete-certificate", err, lager.Data{
					"cert": cert,
				})
			}
		}

		return true
	})
	if err != nil {
		m.logger.Error("iam_list_certificates", err)
	}
}

func (m *RouteManager) RenewAll() {
	routes := []Route{}

	lsession := m.logger.Session("route-manager-renew-all")

	m.logger.Info("Looking for routes that are expiring soon")

	m.db.Having(
		"max(expires) < now() + interval '30 days'",
	).Group(
		"routes.id",
	).Where(
		"state = ?", string(Provisioned),
	).Joins(
		"join certificates on routes.id = certificates.route_id",
	).Find(&routes)

	m.logger.Info("routes-needing-renewal", lager.Data{
		"num-routes": len(routes),
	})

	for _, route := range routes {
		err := m.Renew(&route)
		if err != nil {
			lsession.Error("renew-error", err, lager.Data{
				"domain": route.DomainExternal,
				"origin": route.Origin,
			})
		} else {
			lsession.Info("renew-success", lager.Data{
				"domain": route.DomainExternal,
				"origin": route.Origin,
			})
		}
	}
}

func (m *RouteManager) getDNS01Client(user *utils.User, settings config.Settings) (acme.ClientInterface, error) {
	lsession := m.logger.Session("route-manager-get-dns01-client")

	client, err := m.acmeClientProvider.GetDNS01Client(user, settings)

	if err != nil {
		lsession.Error("new-client-dns-builder", err)
		return client, err
	}

	lsession.Info("new-client-dns-builder-success")
	return client, nil
}

func (m *RouteManager) getHTTP01Client(user *utils.User, settings config.Settings) (acme.ClientInterface, error) {
	lsession := m.logger.Session("route-manager-get-http01-client")

	client, err := m.acmeClientProvider.GetHTTP01Client(user, settings)

	if err != nil {
		lsession.Error("new-client-http-builder", err)
		return client, err
	}

	lsession.Info("new-client-http-builder-success")
	return client, nil
}

func (m *RouteManager) updateProvisioning(r *Route) error {
	lsession := m.logger.Session("route-manager-update-provisioning", lager.Data{
		"instance-id": r.InstanceId,
	})

	user, err := r.loadUser(m.db)
	if err != nil {
		lsession.Error("load-user", err)
		return err
	}

	clients := map[acme.Challenge]acme.ClientInterface{}

	clients[acme.HTTP01], err = m.getHTTP01Client(&user, m.settings)
	if err != nil {
		lsession.Error("get-client-http01", err)
		return err
	}

	clients[acme.DNS01], err = m.getDNS01Client(&user, m.settings)
	if err != nil {
		lsession.Error("get-client-dns01", err)
		return err
	}

	if err := m.ensureChallenges(r, clients[acme.HTTP01]); err != nil {
		lsession.Error("ensure-challenges", err)
		return err
	}

	// Ensure the challenges from LetsEncrypt are persisted in the database
	lsession.Info("db-save-route-challenge")
	err = m.db.Save(r).Error
	if err != nil {
		lsession.Error("db-save-route-challenge-err", err)
	}
	lsession.Info("db-saved-route-challenge")

	isDistributionDeployed := m.checkDistribution(r)

	if !isDistributionDeployed {
		lsession.Info("distribution-provisioning")
		return nil
	}

	var challenges []acme.AuthorizationResource
	if err := json.Unmarshal(r.ChallengeJSON, &challenges); err != nil {
		lsession.Error("challenge-unmarshall", err)
		return err
	}

	// HERE WE NEED TO CHOOSE DNS OR HTTP CHALLENGES

	if errs := m.solveChallenges(clients, challenges); len(errs) > 0 {
		errstr := fmt.Errorf("Error(s) solving challenges: %v", errs)
		lsession.Error("solve-challenges", errstr)
		return errstr
	}

	cert, err := clients[acme.HTTP01].RequestCertificate(challenges, true, nil, false)
	if err != nil {
		lsession.Error("request-certificate-http-01", err)
		return err
	}

	expires, err := acme.GetPEMCertExpiration(cert.Certificate)
	if err != nil {
		lsession.Error("get-cert-expiry", err)
		return err
	}
	if err := m.deployCertificate(*r, cert); err != nil {
		lsession.Error("deploy-certificate", err)
		return err
	}

	certRow := Certificate{
		Domain:      cert.Domain,
		CertURL:     cert.CertURL,
		Certificate: cert.Certificate,
		Expires:     expires,
	}
	if err := m.db.Create(&certRow).Error; err != nil {
		lsession.Error("db-create-cert", err)
		return err
	}

	r.State = Provisioned
	r.Certificate = certRow
	if err := m.db.Save(r).Error; err != nil {
		lsession.Error("db-save-cert", err)
		return err
	}

	return nil
}

func (m *RouteManager) updateDeprovisioning(r *Route) error {
	lsession := m.logger.Session("route-manager-update-deprovisioning")

	deleted, err := m.cloudFront.Delete(r.DistId)
	if err != nil {
		lsession.Error("cloudfront-delete", err)
		return err
	}

	if deleted {
		r.State = Deprovisioned
		if err := m.db.Save(r).Error; err != nil {
			lsession.Error("db-save-delete-state", err)
		}
	}

	return nil
}

func (m *RouteManager) checkDistribution(r *Route) bool {
	dist, err := m.cloudFront.Get(r.DistId)
	if err != nil {
		m.logger.Session("check-distribution").Error("cloudfront-get", err)
		return false
	}

	return *dist.Status == "Deployed" && *dist.DistributionConfig.Enabled
}

func (m *RouteManager) solveChallenges(clients map[acme.Challenge]acme.ClientInterface, challenges []acme.AuthorizationResource) map[string]error {
	startTime := time.Now()
	lsession := m.logger.Session("solve-challenges", lager.Data{
		"start_time": startTime.String(),
	})
	lsession.Info("solve-challenges-start")

	errs := make(chan map[string]error)

	for _, client := range clients {
		go func(client acme.ClientInterface) {
			errs <- client.SolveChallenges(challenges)
		}(client)
	}

	var failures map[string]error
	for challenge := range clients {
		failures = <-errs
		endTime := time.Now()
		lsession.Info("solve-challenges-results", lager.Data{
			"challenge": challenge,
			"failures":  failures,
			"end_time":  endTime.String(),
			"duration":  endTime.Sub(startTime).String(),
		})
		if len(failures) == 0 {
			return failures
		}
	}

	return failures
}

func (m *RouteManager) deployCertificate(route Route, cert acme.CertificateResource) error {
	lsession := m.logger.Session("deploy-certificate", lager.Data{
		"instance-id": route.InstanceId,
		"domains":     route.GetDomains(),
		"dist":        route.DistId,
	})

	lsession.Info("get-cert-expiry")
	expires, err := acme.GetPEMCertExpiration(cert.Certificate)
	if err != nil {
		lsession.Error("get-cert-expiry-err", err)
		return err
	}

	name := fmt.Sprintf("cdn-route-%s-%s", route.InstanceId, expires.Format("2006-01-02_15-04-05"))
	lsession.Info("iam-upload-certificate", lager.Data{"name": name})
	certId, err := m.iam.UploadCertificate(name, cert)
	if err != nil {
		lsession.Error("iam-upload-certificate-err", err, lager.Data{
			"name": name,
		})
		return err
	}

	lsession.Info("iam-set-certificate-and-cname", lager.Data{
		"name":    name,
		"cert_id": certId,
	})
	err = m.cloudFront.SetCertificateAndCname(route.DistId, certId, route.GetDomains())
	if err != nil {
		lsession.Info("iam-set-certificate-and-cname-err", lager.Data{
			"name":    name,
			"cert_id": certId,
			"err":     err,
		})
		return err
	}
	return nil
}

func (m *RouteManager) ensureChallenges(route *Route, client acme.ClientInterface) error {
	lsession := m.logger.Session("ensure-challenges", lager.Data{
		"instance-id": route.InstanceId,
		"domains":     route.GetDomains(),
	})

	if len(route.ChallengeJSON) > 0 {
		lsession.Info("challenge-json-was-already-present")
		return nil
	}

	lsession.Info("get-challenges")
	challenges, errs := client.GetChallenges(route.GetDomains())
	if len(errs) > 0 {
		err := fmt.Errorf("Error(s) getting challenges: %v", errs)
		lsession.Error("get-challenges-err", err)
		return err
	}

	var err error
	route.ChallengeJSON, err = json.Marshal(challenges)
	if err != nil {
		lsession.Error("json-marshal-challenge-err", err)
		return err
	}

	return nil
}

func (m *RouteManager) GetDNSInstructions(route *Route) ([]string, error) {
	var instructions []string
	var challenges []acme.AuthorizationResource

	lsession := m.logger.Session("get-dns-instructions", lager.Data{
		"instance-id": route.InstanceId,
		"domains":     route.GetDomains(),
	})

	lsession.Info("load-user")
	user, err := route.loadUser(m.db)
	if err != nil {
		lsession.Error("load-user-err", err)
		return instructions, err
	}

	if err := json.Unmarshal(route.ChallengeJSON, &challenges); err != nil {
		lsession.Error("json-unmarshal-challenge", err)
		return instructions, err
	}

	lsession.Info("get-key-authorization")
	for _, auth := range challenges {
		for _, challenge := range auth.Body.Challenges {
			if challenge.Type == acme.DNS01 {
				lsession.Info("get-key-authorization-for-a-dns-challenge", lager.Data{"domain": auth.Domain})
				keyAuth, err := acme.GetKeyAuthorization(challenge.Token, user.GetPrivateKey())
				if err != nil {
					lsession.Error("get-key-authorization-err", err)
					return instructions, err
				}
				fqdn, value, ttl := acme.DNS01Record(auth.Domain, keyAuth)
				instructions = append(instructions, fmt.Sprintf("name: %s, value: %s, ttl: %d", fqdn, value, ttl))
			}
		}
	}
	return instructions, nil
}

func (m *RouteManager) GetCurrentlyDeployedDomains(r *Route) ([]string, error) {
	lsession := m.logger.Session("get-currently-deployed-domains")

	lsession.Info("cloudfront-get-start")
	dist, err := m.cloudFront.Get(r.DistId)
	if err != nil {
		lsession.Error("cloudfront-get-error", err)

		return []string{}, err
	}
	lsession.Info("cloudfront-get-done")

	deployedDomains := []string{}
	for _, domain := range dist.DistributionConfig.Aliases.Items {
		deployedDomains = append(deployedDomains, *domain)
	}

	lsession.Info("finished")
	return deployedDomains, nil
}
