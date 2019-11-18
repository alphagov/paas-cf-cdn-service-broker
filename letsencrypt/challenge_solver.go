package letsencrypt

import (
	"code.cloudfoundry.org/lager"
	"fmt"
	"golang.org/x/crypto/acme"
	"net"
	"time"
)

// ChallengeSolverInterface is the abstraction
// over solving an ACME challenge used by
// implementations of CertificateObtainerInterface
//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -o fakes/FakeChallengeSolver.go --fake-name FakeChallengeSolver . ChallengeSolverInterface
type ChallengeSolverInterface interface {
	// Whether the current implementation of ChallengeSolverInterface
	// can solve the type of challenge provided.
	Accept(challenge *acme.Challenge) bool

	// Attempts to validate and/or solve a given challenge.
	//
	// Implementations MUST at least validate the challenge for themselves in some reasonably reliable way
	// and return true when it's valid. If the challenge isn't valid and the implementation returns true,
	// the certificate order will enter the invalid state.
	//
	// Implementations MAY take actions to solve the challenge, as well as validating it.
	TrySolveChallenge(authorization *acme.Authorization, challenge *acme.Challenge, client ClientInterface) (bool, error)
}

type DNS01ChallengeSolver struct {
	logger lager.Logger
}

func NewDNS01ChallengeSolver(logger lager.Logger) ChallengeSolverInterface {
	return DNS01ChallengeSolver{
		logger: logger,
	}
}

func (d DNS01ChallengeSolver) Accept(challenge *acme.Challenge) bool {
	return challenge.Type == ChallengeTypeDNS
}

func (d DNS01ChallengeSolver) TrySolveChallenge(authorization *acme.Authorization, challenge *acme.Challenge, client ClientInterface) (bool, error) {
	logSess := d.logger.Session("dns-record-validation")
	successes := 0
	requiredSuccesses := 5

	logSess.Info("begin", lager.Data{"message": fmt.Sprintf("dns check must succeed %d times in a row", requiredSuccesses)})
StartDNSCheck:
	for {
		logSess.Info("test-record")
		dnsRecordValue, err := client.DNS01ChallengeRecord(challenge.Token)

		if err != nil {
			return false, err
		}

		domain := fmt.Sprintf("_acme-challenge.%s", authorization.Identifier.Value)

		records, err := net.LookupTXT(domain)

		if err != nil {
			return false, err
		}

		for _, r := range records {
			if r == dnsRecordValue {
				successes++
				logSess.Info(
					"record-present",
					lager.Data{
						"message":            "now sleeping for 1 minute, or resolving if the required successes have been met",
						"success":            successes,
						"required_successes": requiredSuccesses,
					},
				)

				if successes >= requiredSuccesses {
					logSess.Info("record-is-valid")
					return true, nil
				}

				time.Sleep(1 * time.Minute)
				continue StartDNSCheck
			}
		}

		return false, nil
	}
}
