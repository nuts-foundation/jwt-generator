// keyring provides utilities for loading and using crypto keys in different formats
package keyring

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Key interface {
	Comment() string
	IsPrivate() bool
	JWASignatureAlgorithm() (jwa.SignatureAlgorithm, error)
	JWK() jwk.Key
	JWKThumbprintSHA256() (string, error)
	JWKThumbprintURI() (string, error)
	PublicKey() (Key, error)
	Raw() (interface{}, error)
	SignJWT(jwt.Token) ([]byte, error)
	SignJWTWithAgent(agent.ExtendedAgent, jwt.Token) ([]byte, error)
	SSHFingerprintSHA256() (string, error)
	SSHPublicKey() (ssh.PublicKey, error)
}

type keyImpl struct {
	comment string
	jwk     jwk.Key
}

// Open reads a key from file, returning a Key
func Open(path string) (Key, error) {
	return OpenWithPassphrase(path, nil)
}

// Open reads a key from file using the provided passphrase, returning a Key
func OpenWithPassphrase(path string, passphrase []byte) (Key, error) {
	// Read the key file
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read %v: %w", path, err)
	}

	return ParseWithPassphrase(keyData, passphrase)
}

// ParseString is a shortcut for calling Parse with a string
func ParseString(s string) (Key, error) {
	return Parse([]byte(s))
}

// Parse parses raw key bytes
func Parse(bytes []byte) (Key, error) {
	return ParseWithPassphrase(bytes, nil)
}

// Parse parses raw key bytes using the provided passphrase
func ParseWithPassphrase(bytes []byte, passphrase []byte) (Key, error) {
	// Try to parse the key as a JWK
	if key, err := jwk.ParseKey(bytes); err == nil {
		jwk.AssignKeyID(key)
		return &keyImpl{jwk: key}, nil
	}

	// Try to parse as PEM
	if key, err := jwk.ParseKey(bytes, jwk.WithPEM(true)); err == nil {
		jwk.AssignKeyID(key)
		return &keyImpl{jwk: key}, nil
	}

	// Try to get a raw crypto/* type from an OpenSSH private key
	if key, err := ssh.ParseRawPrivateKey(bytes); err == nil {
		// Load the raw crypto/* type
		if converted, err := from(key); err == nil {
			// Read the SSH key comment with a special function, since private key comments are
			// not parsed by the x/crypto/ssh library even though the data is stored in the file.
			if comment, err := sshPrivateKeyComment(bytes); err == nil {
				// Apply the comment field value
				converted.comment = comment
			} else {
				// Return an error if comment parsing failed
				return nil, fmt.Errorf("failed to read comment: %v", err)
			}

			// Return the loaded key
			return converted, nil
		} else {
			return nil, err
		}

		// Handle the ssh.PassphraseMissingError error type
	} else if _, ok := err.(*ssh.PassphraseMissingError); ok {
		// If no passphrase was provided then return the error directly to
		// indicate the caller must provide a passphrase to parse this key
		if len(passphrase) == 0 {
			return nil, err
		}

		// Try to get a raw crypto/* type from an OpenSSH passphrase protected key
		if key, err := ssh.ParseRawPrivateKeyWithPassphrase(bytes, passphrase); err == nil {
			// Load the raw crypto/* type
			if converted, err := from(key); err == nil {
				// Return the loaded key
				return converted, nil
			} else {
				return nil, err
			}
		}
	}

	// Try to parse as OpenSSH public key
	if key, err := ssh.ParsePublicKey(bytes); err == nil {
		// Convert the ssh.PublicKey from ParsePublicKey
		if converted, err := from(key); err == nil {
			// Return the loaded key
			return converted, nil
		} else {
			return nil, err
		}
	}

	// Try to parse as OpenSSH authorized key
	if key, comment, _, _, err := ssh.ParseAuthorizedKey(bytes); err == nil {
		// Convert the ssh.PublicKey from ParseAuthorizedKey
		if converted, err := from(key); err == nil {
			// Apply the comment value from ParseAuthorizedKey
			converted.comment = comment

			// Return the loaded key
			return converted, nil
		} else {
			return nil, err
		}
	}

	return nil, errors.New("failed to parse as JWK, PEM, or OpenSSH private/public/authorized key")
}

// From creates a Key from go crypto/* types
func From(raw interface{}) (Key, error) {
	return from(raw)
}

// from creates a keyImpl from go crypto/* & jwx types
func from(raw interface{}) (*keyImpl, error) {
	// Handle ssh.CryptoPublicKey types
	if cryptoPublicKey, ok := raw.(ssh.CryptoPublicKey); ok {
		if convertedToJWK, err := jwk.FromRaw(cryptoPublicKey.CryptoPublicKey()); err == nil {
			jwk.AssignKeyID(convertedToJWK)
			return &keyImpl{jwk: convertedToJWK}, nil
		}
	}

	// Handle other types more directly
	switch raw := raw.(type) {
	// Handle ssh-agent keys, which do not implement the ssh.CryptoPublicKey interface, by
	// marshalling the public key to ssh wire format then loading the key using
	// ssh.ParsePublicKey(). This returns a type that implements the ssh.CryptoPublicKey
	// interface. Using the resulting ssh.CryptoPublicKey interface it is possible to
	// get the crypto/* raw types, which can be used to create a JWK, and thus a keyImpl.
	case *agent.Key:
		// Dump the public key from the agent in ssh wire format
		wireFormat := raw.Marshal()

		// Parse the wire format dump of the key using non-agent functions
		sshPublicKey, err := ssh.ParsePublicKey(wireFormat)
		if err != nil {
			return nil, fmt.Errorf("failed to parse wire-formatted key: %v", err)
		}

		// Use the ssh.CryptoPublicKey interface to access the raw cryto/* type of the key
		if cryptoPublicKey, ok := sshPublicKey.(ssh.CryptoPublicKey); ok {
			// Create a JWK based on the resulting public key
			if convertedToJWK, err := jwk.FromRaw(cryptoPublicKey.CryptoPublicKey()); err == nil {
				// Assign the key ID to the JWK
				jwk.AssignKeyID(convertedToJWK)

				// Return a keyImpl based on the JWK
				return &keyImpl{jwk: convertedToJWK}, nil
			}
		}

		// Return an error if the ssh.CryptoPublicKey interface could not be used
		return nil, fmt.Errorf("failed to convert %T to ssh.CryptoPublicKey", raw)
	case *ed25519.PrivateKey:
		if convertedToJWK, err := jwk.FromRaw(*raw); err == nil {
			jwk.AssignKeyID(convertedToJWK)
			return &keyImpl{jwk: convertedToJWK}, nil
		}
	default:
		if convertedToJWK, err := jwk.FromRaw(raw); err == nil {
			jwk.AssignKeyID(convertedToJWK)
			return &keyImpl{jwk: convertedToJWK}, nil
		}
	}
	return nil, fmt.Errorf("failed to convert %T", raw)
}

// JWK returns the key as a jwk.Key
func (k *keyImpl) JWK() jwk.Key {
	return k.jwk
}

// PublicKey returns the corresponding public key for private keys
func (k *keyImpl) PublicKey() (Key, error) {
	// Ensure this key is a private key
	if !k.IsPrivate() {
		return nil, errors.New("unable to create public key without a private key")
	}

	// Get the raw key
	raw, err := k.Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}

	// If the raw type implements crypto.Signer then use that to return the public key
	if signer, ok := raw.(crypto.Signer); ok {
		return From(signer.Public())
	}

	return nil, fmt.Errorf("raw type %T does not implement crypto.Signer", raw)
}

// SignJWT signs a jwt.Token and returns the encoded token
func (k *keyImpl) SignJWT(token jwt.Token) ([]byte, error) {
	// Determine which signature algorithm should be used
	signatureAlgorithm, err := k.JWASignatureAlgorithm()
	if err != nil {
		return nil, fmt.Errorf("failed to determine signature algorithm: %w", err)
	}

	// Create the signing option for this key
	signOption := jwt.WithKey(signatureAlgorithm, k.jwk)

	// Create the new serializer
	serializer := jwt.NewSerializer().Sign(signOption)

	// Serialize the token, returning any associated error as well
	return serializer.Serialize(token)
}

// SignJWTWithAgent signs a jwt.Token using an ssh-agent and returns the encoded compact token
func (k *keyImpl) SignJWTWithAgent(agentClient agent.ExtendedAgent, token jwt.Token) ([]byte, error) {
	// Determine the key ID of this key
	signingKeyFingerprint, err := k.SSHFingerprintSHA256()
	if err != nil {
		return nil, fmt.Errorf("failed to create fingerprint: %w", err)
	}

	// Get the list of keys loaded in the agent
	agentKeys, err := agentClient.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys in agent: %w", err)
	}

	// Determine whether the key we want to sign with is loaded in the agent
	keyIsLoaded := func() bool {
		// Iterate over the keys loaded in the agent
		for _, agentKey := range agentKeys {
			// Compute the fingerprint of this key
			agentKeyFingerprint := ssh.FingerprintSHA256(agentKey)

			// Compare the fingerprint to that of the key we want to sign with
			if agentKeyFingerprint == signingKeyFingerprint {
				// Return true when the fingreprints match
				return true
			}
		}

		// Return false, as no loaded keys matched the signing key fingerprint
		return false
	}()

	// Return an error if the signing key isn't loaded into the ssh-agent
	if !keyIsLoaded {
		return nil, fmt.Errorf("signing key is not loaded in ssh-agent")
	}

	// Determine which signature algorithm should be used
	signatureAlgorithm, err := k.JWASignatureAlgorithm()
	if err != nil {
		return nil, fmt.Errorf("failed to determine signature algorithm: %w", err)
	}

	// Create the protected headers for the JWT
	protectedHeaders := jws.NewHeaders()
	protectedHeaders.Set(jws.AlgorithmKey, signatureAlgorithm)
	protectedHeaders.Set(jws.TypeKey, "JWT")
	protectedHeaders.Set(jws.KeyIDKey, signingKeyFingerprint)
	protectedHeadersJSON, err := json.Marshal(protectedHeaders)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize protected headers: %w", err)
	}

	// Create the payload to be signed
	tokenJSON, err := jwt.NewSerializer().Serialize(token)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize token: %w", err)
	}

	// Create the string to sign
	stringToSign := fmt.Sprintf("%s.%s", protectedHeadersJSON, tokenJSON)

	// Create the signature
	signature, err := func() ([]byte, error) {
		// Get the ssh.PublicKey of the signing key
		publicKey, err := k.SSHPublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to get ssh.PublicKey: %w", err)
		}

		// Create the signature differently depending on the signature algorithm
		switch signatureAlgorithm {
		// PS512 signatures need to be made with SignWithFlags() since RSA keys will by default use an insecure
		// signing method
		case jwa.PS512:
			sshSignature, err := agentClient.SignWithFlags(publicKey, []byte(stringToSign), agent.SignatureFlagRsaSha512)
			if err != nil {
				return nil, err
			}
			return sshSignature.Blob, nil

		// Most signatures are performed using the default Sign() method
		case jwa.EdDSA, jwa.ES256, jwa.ES384, jwa.ES512:
			sshSignature, err := agentClient.Sign(publicKey, []byte(stringToSign))
			if err != nil {
				return nil, err
			}
			return sshSignature.Blob, nil

		// Only perform explicitly supported signature algorithms
		default:
			return nil, fmt.Errorf("unsupported signature algorithm: %s", signatureAlgorithm)
		}
	}()

	// Check for signing errors
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Create a new JWM (JSON Web Message) with the payload, headers, and signature
	message := jws.NewMessage().
		SetPayload(tokenJSON).
		AppendSignature(
			jws.NewSignature().
				SetProtectedHeaders(protectedHeaders).
				SetSignature(signature),
		)

	// Encode the JWM in compact format
	encoded, err := jws.Compact(message)
	if err != nil {
		return nil, fmt.Errorf("failed to encode compact message: %w", err)
	}

	// Return the JWT as an encoded compact message
	return encoded, nil
}

// IsPrivate returns true if this is an asymmetric private key
func (k *keyImpl) IsPrivate() bool {
	// Inspect the raw key to determine whether it is a private key
	raw, _ := k.Raw()
	switch raw.(type) {
	case ed25519.PrivateKey:
		return true
	case *rsa.PrivateKey:
		return true
	case *ecdsa.PrivateKey:
		return true
	}
	return false
}

// Raw returns the raw crypto/* type of the key
func (k *keyImpl) Raw() (interface{}, error) {
	// Convert the key to its raw key type from crypto/*
	var rawKey interface{}
	if err := k.jwk.Raw(&rawKey); err != nil {
		return nil, fmt.Errorf("unable to convert to raw key: %w", err)
	}

	return rawKey, nil
}

// JWASignatureAlgorithm returns the appropriate jwa.SignatureAlgorithm for use with the key
func (k *keyImpl) JWASignatureAlgorithm() (jwa.SignatureAlgorithm, error) {
	keyType := k.jwk.KeyType()
	switch keyType {
	// Handle elliptic curve keys
	case jwa.EC:
		// Get the curve of the key
		curve, _ := k.jwk.Get(jwk.ECDSACrvKey)

		// Determine the signature algorithm based on the key's curve
		switch curve {
		// ECDSA P-256 keys use the ES256 signature algorithm
		case jwa.P256:
			return jwa.ES256, nil
		// ECDSA P-384 keys use the ES384 signature algorithm
		case jwa.P384:
			return jwa.ES384, nil
		// ECDSA P-521 (sic) keys use the ES512 (sic) signature algorithm
		case jwa.P521:
			return jwa.ES512, nil
		}

		// Ensure unhandled curves result in an error
		return "", fmt.Errorf("Unhandled EC curve (%T): %+v", curve, curve)
	// Handle octet key pair keys
	case jwa.OKP:
		// Get the curve of the key
		curve, _ := k.jwk.Get(jwk.OKPCrvKey)

		// Determine the signature algorithm based on the key's curve
		switch curve {
		// Ed25519 keys use the EdDSA signature algorithm
		case jwa.Ed25519:
			return jwa.EdDSA, nil
		}

		// Ensure unhandled curves result in an error
		return "", fmt.Errorf("Unhandled OKP curve (%T): %+v", curve, curve)
	// Handle RSA key types
	case jwa.RSA:
		// There are many algorithms that can be used with RSA keys, but PS512 offers
		// better security compared to RS256, RS384, RS512, PS256, and PS384 algorithms
		return jwa.PS512, nil
	default:
		return "", fmt.Errorf("unsupported %T %+v", keyType, keyType)
	}
	// Convert the key to its raw crypto/* type
	raw, err := k.Raw()
	if err != nil {
		return jwa.NoSignature, err
	}

	// Determine the type of the key
	switch raw := raw.(type) {
	case *ecdsa.PrivateKey:
		// ECDSA256 keys use the ES256 signature algorithm
		if raw.Curve == elliptic.P256() {
			return jwa.ES256, nil
		}

		// ECDSA384 keys use the ES384 signature algorithm
		if raw.Curve == elliptic.P384() {
			return jwa.ES384, nil
		}

		// ECDSA521 (sic) keys use the ES512 (sic) signature algorithm
		if raw.Curve == elliptic.P521() {
			return jwa.ES512, nil
		}
	case *ecdsa.PublicKey:
		// ECDSA256 keys use the ES256 signature algorithm
		if raw.Curve == elliptic.P256() {
			return jwa.ES256, nil
		}

		// ECDSA384 keys use the ES384 signature algorithm
		if raw.Curve == elliptic.P384() {
			return jwa.ES384, nil
		}

		// ECDSA521 (sic) keys use the ES512 (sic) signature algorithm
		if raw.Curve == elliptic.P521() {
			return jwa.ES512, nil
		}
	}

	return jwa.NoSignature, fmt.Errorf("No known signature algorithms for %T: %+v", raw, raw)
}

// JWKThumbprintSHA256 returns the base64 encoded SHA256 JWK thumbprint of the key per RFC7638
func (k *keyImpl) JWKThumbprintSHA256() (string, error) {
	// Generate the SHA256 thumbprint
	hash, err := k.jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to generate thumbprint: %v", err)
	}

	// Return the base64 hash
	return base64.RawURLEncoding.EncodeToString(hash), nil
}

// JWKThumbprintURI returns the JWK thumbprint of the key as a URI (e.g. urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs)
func (k *keyImpl) JWKThumbprintURI() (string, error) {
	// Generate the thumbprint
	thumbprint, err := k.JWKThumbprintSHA256()
	if err != nil {
		return "", err
	}

	// Return the thumbprint as a URI
	return fmt.Sprintf("urn:ietf:params:oauth:jwk-thumbprint:sha-256:%s", thumbprint), nil
}

// SSHPublicKey converts the public key component of the key into an ssh.PublicKey
func (k *keyImpl) SSHPublicKey() (ssh.PublicKey, error) {
	// Get the raw crypto/* key
	raw, err := k.Raw()
	if err != nil {
		return nil, err
	}

	// For the following steps we will ultimately need an ssh public key
	var publicKey ssh.PublicKey

	// Convert the rawKey into an SSH signer, which works if rawKey is a private key, but not public key
	if signer, err := ssh.NewSignerFromKey(raw); err == nil {
		publicKey = signer.PublicKey()
	} else {
		// Since creating a signer from the key failed perhaps we were given a public key, so try
		// creating an ssh.PublicKey directly from the rawKey
		if publicKey, err = ssh.NewPublicKey(raw); err != nil {
			return nil, fmt.Errorf("unable to create ssh.Signer or ssh.PublicKey from %T", raw)
		}
	}

	return publicKey, nil
}

// SSHFingerprintSHA256 returns the ssh SHA256 fingerprint of the key
func (k *keyImpl) SSHFingerprintSHA256() (string, error) {
	publicKey, err := k.SSHPublicKey()
	if err != nil {
		return "", err
	}

	return ssh.FingerprintSHA256(publicKey), nil
}

// Comment returns text about the key, usually an associated username/email address
func (k *keyImpl) Comment() string {
	return k.comment
}

// sshPrivateKeyComment parses files per https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
func sshPrivateKeyComment(keyBytes []byte) (string, error) {
	block, _ := pem.Decode(keyBytes)
	if block.Type != "OPENSSH PRIVATE KEY" {
		return "", fmt.Errorf("unhandled block type %s", block.Type)
	}

	magic := append([]byte("openssh-key-v1"), 0)
	if !bytes.Equal(magic, block.Bytes[0:len(magic)]) {
		return "", errors.New("ssh: invalid openssh private key format")
	}

	remaining := block.Bytes[len(magic):]
	var w struct {
		CipherName string
		KdfName    string
		KdfOpts    string
		NumKeys    uint32
		Rest       []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(remaining, &w); err != nil {
		return "", err
	}

	if w.KdfName != "none" || w.CipherName != "none" {
		return "", errors.New("ssh: cannot decode encrypted private keys")
	}

	remaining = w.Rest
	var pubKeyData struct {
		PubKey []byte
		Rest   []byte `ssh:"rest"`
	}
	for x := uint32(0); x < w.NumKeys; x++ {
		if err := ssh.Unmarshal(remaining, &pubKeyData); err != nil {
			return "", err
		}
		remaining = pubKeyData.Rest
	}

	remaining = pubKeyData.Rest
	var packedPrivateKeys struct {
		Packed []byte
		Rest   []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(remaining, &packedPrivateKeys); err != nil {
		return "", err
	}

	remaining = packedPrivateKeys.Packed
	var checkInts struct {
		Check1 uint32
		Check2 uint32
		Rest   []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(remaining, &checkInts); err != nil {
		return "", fmt.Errorf("failed to read check ints: %v", err)
	}
	if checkInts.Check1 != checkInts.Check2 {
		return "", fmt.Errorf("bad checkints")
	}

	remaining = checkInts.Rest
	for x := uint32(0); x < w.NumKeys; x++ {
		var privateKeyType struct {
			Type string
			Rest []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(remaining, &privateKeyType); err != nil {
			return "", fmt.Errorf("failed to read private key: %v", err)
		}

		remaining = privateKeyType.Rest
		switch privateKeyType.Type {
		case ssh.KeyAlgoRSA:
			// https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L2760-L2773
			key := struct {
				Skip1   *big.Int
				Skip2   *big.Int
				Skip3   *big.Int
				Skip4   *big.Int
				Skip5   *big.Int
				Skip6   *big.Int
				Comment string
				Rest    []byte `ssh:"rest"`
			}{}

			if err := ssh.Unmarshal(remaining, &key); err != nil {
				return "", err
			}

			return key.Comment, nil

		case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
			key := struct {
				Curve   string
				Skip1   *big.Int
				Skip2   *big.Int
				Comment string
				Rest    []byte `ssh:"rest"`
			}{}

			if err := ssh.Unmarshal(remaining, &key); err != nil {
				return "", err
			}

			return key.Comment, nil

		case ssh.KeyAlgoED25519:
			key := struct {
				Skip1   []byte
				Skip2   []byte
				Comment string
				Rest    []byte `ssh:"rest"`
			}{}

			if err := ssh.Unmarshal(remaining, &key); err != nil {
				return "", err
			}

			return key.Comment, nil
		default:
			return "", fmt.Errorf("unhandled key type %s", privateKeyType.Type)
		}
	}

	return "", errors.New("no private keys to unpack")
}
