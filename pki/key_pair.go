package pki

// KeyPair is a dumb container for private key and cert
type KeyPair struct {
	PrivateKey  []byte
	Certificate []byte
}
