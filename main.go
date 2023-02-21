// A JWT generator for authenticating to nuts-node services
package main

import (
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"net"
	"strings"
	"syscall"
	"time"

	// The ssh library is used to access ssh key metadata returned from the ssh-agent
	"golang.org/x/crypto/ssh"

	// The ssh agent library is used to perform signing operations within an ssh-agent
	"golang.org/x/crypto/ssh/agent"

	// The term library is used to read passwords from the terminal
	"golang.org/x/term"

	// The jwx library is used to build tokens, but signing is performed outside the library
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	// The uuid library is used to generate JWT IDs
	"github.com/google/uuid"
)

type signingFunc func([]byte) (*ssh.Signature, error)

// store the command line arguments in a global struct
var arguments struct {
	duration int
	host string

	agentKey string
	keyFilePath string

	exportAuthorizedKey bool
	exportJWKThumbprint bool
	exportSSHFingerprint bool
	listKeys bool
	verbose bool
}

// init sets up the command line arguments
func init() {
	flag.StringVar(&arguments.host, "host", "", "hostname of nuts node")
	flag.StringVar(&arguments.agentKey, "key", "", "agent key specification")
	flag.StringVar(&arguments.keyFilePath, "i", "", "key file path")
	flag.BoolVar(&arguments.listKeys, "list", false, "list SSH keys from ssh-agent")
	flag.BoolVar(&arguments.verbose, "verbose", false, "enable logging output")
	flag.IntVar(&arguments.duration, "duration", 300, "duration in seconds of the token validity")
	flag.BoolVar(&arguments.exportAuthorizedKey, "export-authorized-key", false, "Export the authorized_keys format")
	flag.BoolVar(&arguments.exportJWKThumbprint, "export-jwk-thumbprint", false, "Export the JWK SHA256 thumbprint")
	flag.BoolVar(&arguments.exportSSHFingerprint, "export-ssh-fingerprint", false, "Export the SSH SHA256 fingerprint")
}

func main() {
	// Parse command line arguments
	flag.Parse()

	// Check command line syntax
	if !arguments.listKeys && !arguments.exportAuthorizedKey && !arguments.exportSSHFingerprint && !arguments.exportJWKThumbprint && arguments.host == "" {
		log.Fatal("syntax error: missing host argument")
	}
	
	// Disable logging unless --verbose was specified
	if !arguments.verbose {
		log.SetOutput(io.Discard)
	}

	// Optionally export the key in authorized_keys format
	if arguments.exportAuthorizedKey {
		exportAuthorizedKey(arguments.keyFilePath)
		return
	}

	// Optionally export the key fingerprint in SSH SHA256 format
	if arguments.exportSSHFingerprint {
		exportSSHFingerprint(arguments.keyFilePath)
		return
	}

	// Optionally export the key thumbprint in JWK SHA256 format
	if arguments.exportJWKThumbprint {
		exportJWKThumbprint(arguments.keyFilePath)
		return
	}

	// Optionally list the keys available in the ssh-agent
	if arguments.listKeys {
		listSSHKeys(connectAgent())
		return
	}

	// If an ssh key file was specified with -i then use that path, otherwise
	// sign the key using ssh-agent
	if arguments.keyFilePath != "" {
		// Load the key from the filesystem
		key := parseKeyFile(arguments.keyFilePath)

		// Get the JWK key ID of this SSH key
		keyID := keyFileBasedKeyID(key)
		log.Printf("kid: %v", keyID)

		// Build the payload of the JWT using the command line arguments
		payload := buildPayload(arguments.host, arguments.duration, defaultKeyComment())

		// Setup the key file based signer
		signer := keyFileBasedSigningFunc(key)

		// Sign and print the token
		token := signPayload(keyID, signer, payload)
		fmt.Printf("%v\n", token)
	} else {
		// Connect to the ssh-agent
		agentClient := connectAgent()


		// Select the key for authenticating to the API
		key, err := selectSSHKey(agentClient, arguments.agentKey)
		if err != nil {
			log.Fatalf("failed to find ssh-agent key (%v): %v", arguments.agentKey, err)
		}

		// Get the JWK key ID of this SSH key
		keyID := agentBasedKeyID(key)
		log.Printf("kid: %v", keyID)

		// Build the payload of the JWT using the command line arguments
		payload := buildPayload(arguments.host, arguments.duration, key.Comment)

		// Setup the agent based signer
		signer := agentBasedSigningFunc(agentClient, key)

		// Sign and print the token
		token := signPayload(keyID, signer, payload)
		fmt.Printf("%v\n", token)
	}
}

// keyFileBasedSigningFunc takes an SSH private key (interface{} as it can be many types) and returns
// a signingFunc to be used for signing tokens. The resulting signatures are of various types depending
// on the key type provided.
func keyFileBasedSigningFunc(key interface{}) signingFunc {
	log.Printf("signingFunc from %+v", key)
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		log.Fatalf("failed to create signer from key: %v", err)
	}

	// The default signature type returned from RSA keys is by default ambiguous and insecure,
	// so we need to force a type conversion to the AlgorithmSigner interface which allows
	// specifying the algorithm used in the signing process. All Signer types generated by the
	//  go ssh package should enforce this so we expect this to always work.
	//
	// See the TestKeySignWithAlgorithmVerify method here:
	// https://go.googlesource.com/crypto/+/master/ssh/keys_test.go#113
	if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		if algoSigner, ok := signer.(ssh.AlgorithmSigner); ok {
			return func(plaintext []byte) (*ssh.Signature, error) {
				return algoSigner.SignWithAlgorithm(rand.Reader, plaintext, ssh.KeyAlgoRSASHA512)
			}
		}
		log.Fatalf("failed to create AlgorithmSigner from KeyAlgoRSA signer")
	}

	// For most key types rely on the default Sign() method which auto-selects a signature algorithm
	// based on the key type
	return func(plaintext []byte) (*ssh.Signature, error) {
		return signer.Sign(rand.Reader, plaintext)
	}
}

// agentBasedSigningFunc returns a signingFunc which signs plaintext using the specified key in the
// ssh-agent. The returned signatures are of various formats depending on the key type.
func agentBasedSigningFunc(agentClient agent.ExtendedAgent, key *agent.Key) signingFunc {
	// The default signature type returned from RSA keys is by ambiguous and insecure, so we need
	// to use SignWithFlags() to specify a particular signing algorithm instead of relying on
	// the default like we do with most key types.
	//
	// See https://pkg.go.dev/golang.org/x/crypto/ssh/agent#ExtendedAgent
	log.Printf("key: %+v", key)
	if key.Format == ssh.KeyAlgoRSA {
		return func(plaintext []byte) (*ssh.Signature, error) {
			return agentClient.SignWithFlags(key, plaintext, agent.SignatureFlagRsaSha512)
		}
	}

	// For most key types rely on the default Sign() method which auto-selects a signature algorithm
	// based on the key type
	return func(plaintext []byte) (*ssh.Signature, error) {
		return agentClient.Sign(key, plaintext)
	}
}

func parseKeyFile(path string) interface{} {
	// Read the key file
	contents, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to read %v: %v", path, err)
	}

	// Parse the key file
	key, err := ssh.ParseRawPrivateKey(contents)
	if err != nil {
		// Handle errors due to passphrase protected key files
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			// Read the passphrase for the key file from stdin
			passphrase, err := readPassword("key passphrase: ")

			// All following cases should explicitly zero out the passphrase bytes, but
			// defer a zero operation here to ensure that the bytes are zero'ed out when
			// this function returns even if such a bug arises. Is this paranoid? Yes
			defer zero(passphrase)

			if err != nil {
				// It is unlikely that an error condition will also return passphrase bytes,
				// but out of paranoia zero out any buffer returned prior to handling the
				// error condition, as log.Fatal* causes defer() methods to be skipped
				zero(passphrase)
				log.Fatalf("failed to read key passphrase from stdin: %v", err)
			}

			// Retry the key parsing using the provided passphrase
			key, err := ssh.ParseRawPrivateKeyWithPassphrase(contents, passphrase)

			// Zero out the passphrase bytes as it is not needed anymore and could be
			// swapped out to disk if it remains in memory
			zero(passphrase)

			// Check for errors in parsing the key file with the passphrase
			if err != nil {
				log.Fatalf("failed to parse %v with passphrase: %v", path, err)
			}

			return key
		// Errors for any reason other than passphrase protection are fatal
		} else {
			log.Fatalf("failed to parse %v: %v", arguments.keyFilePath, err)
		}
	}

	return key
}

func buildPayload(host string, duration int, user string) []byte {
	// Determine the time to use for the JWT
	now := time.Now()
	expires := now.Add(time.Second * time.Duration(duration))

	// Create the JWT
	token, err := jwt.NewBuilder().
		JwtID(uuid.NewString()).
		Subject(user).
		Issuer(user).
		IssuedAt(now).
		NotBefore(now).
		Expiration(expires).
		Audience([]string{host}).
		Build()
	if err != nil {
		log.Fatalf("failed to build token: %+v", err)
	}

	// Serialize the token which will be signed
	serializedToken, err := jwt.NewSerializer().Serialize(token)
	if err != nil {
		log.Fatalf("failed to serialize token: %+v: %+v", token, err)
	}

	return serializedToken
}

func signPayload(keyID string, signer signingFunc, payload []byte) string {
	// Produce an example signature for getting basic parameters out
	exampleSignature, err := signer([]byte("A"))
	if err != nil {
		log.Fatalf("failed to create example signature: %v", err)
	}

	// Build the JWT headers
	headers := make(map[string]string)
	headers["typ"] = "JWT"
	headers["kid"] = keyID
	headers["alg"] = jwtAlgFromSSHSignature(exampleSignature)
	serializedHeaders, err := json.Marshal(headers)
	if err != nil {
		log.Fatalf("failed to serialize headers: %v", err)
	}
	log.Printf("headers: %+v", headers)

	stringToSign := b64.RawURLEncoding.EncodeToString(serializedHeaders) + "." + b64.RawURLEncoding.EncodeToString(payload)
	log.Printf("stringToSign: %v", stringToSign)

	// Produce the actual signature for the final JWT
	signature, err := signer([]byte(stringToSign))
	if err != nil {
		log.Fatalf("failed to sign empty string: %v", err)
	}
	
	// Assemble the final JWT
	return stringToSign + "." + b64.RawURLEncoding.EncodeToString(signature.Blob)
}

// connectAgent returns a connected client for the ssh-agent
func connectAgent() agent.ExtendedAgent {
	// ssh-agent(1) provides a UNIX socket at $SSH_AUTH_SOCK.
	socket := os.Getenv("SSH_AUTH_SOCK")
	connection, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}

	return agent.NewClient(connection)
}

// jwtAlgFromSSHSignature returns the JWT signature algorithm that corresponds to the given SSH signature format.
// The strings identifying algorithms within the SSH system are different from the strings identifying algorithms
// within the JWT system, which is the primary reason this function is required.
func jwtAlgFromSSHSignature(signature *ssh.Signature) string {
	switch signature.Format {

	// Define the translations for ECDSA signature algorithms
	// See https://docs.mashery.com/connectorsguide/GUID-B5131DD5-C60F-4979-81C3-E0FC79ABA309.html
	case ssh.KeyAlgoECDSA256:
		return "ES256"
	case ssh.KeyAlgoECDSA384:
		return "ES384"
	case ssh.KeyAlgoECDSA521:
		return "ES512"

	// Define the translation for Edwards curve signatures
	// See https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-eddsa
	case ssh.KeyAlgoED25519:
		return "EdDSA"

	// Define translations for RSA signatures
	case ssh.KeyAlgoRSA:
		// This should not occur since we are specifically selecting the algorithm type
		// when using RSA keys for signing operations, but this error message is here
		// just in case a bug or otherwise unexpected behaviour occurs in an ssh-agent.
		//
		// See https://ikarus.sg/rsa-is-not-dead/
		//
		// TL;DR: This should never occur, and if we were to allow it to occur it could
		// be dangerous.
		log.Fatalf("ssh-rsa signatures are forbidden; rsa-sha2-512 was expected instead")
	case ssh.KeyAlgoRSASHA256:
		return "RS256"
	case ssh.KeyAlgoRSASHA512:
		return "RS512"

	// Signatures other than the types defined above are unexpected and unsupported
	default:
		log.Fatalf("unsupported signature format: %+v", signature)
	}

	// This point should be unreachable due to the default case above, but this
	// satisfies a compiler error about missing returns and protects against bugs
	// in the above code.
	panic("unreachable")
}

func listSSHKeys(agentClient agent.Agent) {
	// List the keys available in the ssh-agent
	keys, err := agentClient.List()
	if err != nil {
		log.Fatalf("error listing agent keys: %+v", err)
	}

	// Print a description of each key
	for _, key := range keys {
		fmt.Printf("%v\n", describeKey(key))
	}
}

func selectSSHKey(agentClient agent.Agent, keySpec string) (*agent.Key, error) {
	// List the keys available in the ssh-agent
	keys, err := agentClient.List()

	// Forward any errors listing keys to the caller
	if err != nil {
		return nil, err
	}

	// Search for the key specified by the user
	for _, key := range keys {
		if strings.Contains(describeKey(key), keySpec) {
			return key, nil
		}
	}

	return nil, nil
}

// describeKey returns a string representation of an SSH key hosted in an ssh-agent
func describeKey(key *agent.Key) string {
	return fmt.Sprintf("%v %v %v", key.Format, b64.StdEncoding.EncodeToString(key.Blob), key.Comment)
}

// zero sets the bytes in a slice of bytes to zero values
func zero(slice []byte) {
	// nil slices can't be zero'd, so just return
	if slice == nil {
		return
	}

	// Loop over the available indices and set the bytes to 0
	for index := range slice {
		slice[index] = 0
	}
}

// defaultKeyComment returns a default comment based on the current username/hostname. This is
// to be used when a key comment is not available (the embedded comments in file based keys do
// not seem to be accessible via x/crypto/ssh -- so this is used for the time being).
func defaultKeyComment() string {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("failed to get user: %v", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("failed to get hostname: %v", err)
	}

	return fmt.Sprintf("%v@%v", currentUser.Username, hostname)
}

// readPassword implements a workaround for term.ReadPassword() as described in
// https://github.com/golang/go/issues/31180#issuecomment-1133854964
func readPassword(prompt string) ([]byte, error) {
	// Print the password prompt
	fmt.Printf(prompt)

	// Get the file handle number for stdin
	stdin := int(syscall.Stdin)

	// Read the state of the stdin terminal
	oldState, err := term.GetState(stdin)
	if err != nil {
		return nil, err
	}

	// Restore the state of the stdin terminal upon returning from this function
	defer term.Restore(stdin, oldState)

	// Listen for interrupt signals on a channel
	sigch := make(chan os.Signal, 1)
	signal.Notify(sigch, os.Interrupt)

	// Stop listening for interrupt signals on this channel when this function returns
	defer signal.Reset(os.Interrupt)

	// Handle interrupt signals received on that channel
	go func() {
		// Wait for a signal to arrive on the channel, e.g. a CTRL-C event
		for _ = range sigch {
			// Restore the state of the terminal
			term.Restore(stdin, oldState)

			// Exit with status 130, which is the usual exit code for processes
			// stopped with CTRL-C	
			os.Exit(130)
		}
	}()

	// Read a password from the terminal using term.ReadPassword(), which sets noecho, meaning
	// typed characters are not shown on the terminal
	password, err := term.ReadPassword(stdin)
	if err != nil {
		return nil, err
	}

	// Print a new line character, as the user's return key would not have shown on the terminal
	// in the noecho mode set by term.ReadPassword()
	fmt.Printf("\n")

	// Return the password that was read, triggering the defer calls above
	return password, nil
}

func keyFileBasedKeyID(key interface{}) string {
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		log.Fatalf("failed to create signer from key: %v", err)
	}

	return ssh.FingerprintSHA256(signer.PublicKey())
}

func agentBasedKeyID(key *agent.Key) string {
	return ssh.FingerprintSHA256(key)
}

func exportAuthorizedKey(path string) {
	// Load an SSH public key from the given path
	publicKey := loadSSHPublicKey(path)

	// Print the authorized_keys entry format for the given public key
	authorizedKey := ssh.MarshalAuthorizedKey(publicKey)
	fmt.Println(string(authorizedKey))
}

func exportSSHFingerprint(path string) {
	// Load an SSH public key from the given path
	publicKey := loadSSHPublicKey(path)

	// Generate and print the fingerprint
	fingerprint := ssh.FingerprintSHA256(publicKey)
	fmt.Println(fingerprint)
}

func exportJWKThumbprint(path string) {
	// Load the JWK key stored in the file
	key := loadJWKKey(path)

	// Build the JWK thumbprint for the key
	jwk.AssignKeyID(key)

	// Print the generated key ID
	fmt.Println(key.KeyID())
}

func loadJWKKey(path string) jwk.Key {
	// Ensure a path was passed
	if path == "" {
		log.Fatal("missing key file argument -i")
	}

	// Read the key file
	keyData, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("unable to read %v: %v", path, err)
	}

	// Try to parse the key as a JWK, then PEM if that doesn't work
	var key jwk.Key
	key, err = jwk.ParseKey(keyData)
	if err != nil {
		log.Printf("unable to parse %v as JWK, trying PEM: %v", path, err)

		// Try to parse again as PEM
		key, err = jwk.ParseKey(keyData, jwk.WithPEM(true))
		if err != nil {
			log.Fatalf("unable to parse %v as PEM, giving up: %v", path, err)
		}
	}

	return key
}

func loadSSHPublicKey(path string) ssh.PublicKey {
	// Load the jwk.Key contained in this path
	key := loadJWKKey(path)

	// Convert the key to its raw key type from crypto/*
	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		log.Fatalf("unable to convert to raw key: %v", err)
	}

	// For the following steps we will ultimately need an ssh public key
	var pubKey ssh.PublicKey

	// Convert the rawKey into an SSH signer, which works if rawKey is a private key, but not public key
	if signer, err := ssh.NewSignerFromKey(rawKey); err == nil {
		pubKey = signer.PublicKey()
	} else {
		// Since creating a signer from the key failed perhaps we were given a public key, so try
		// creating an ssh.PublicKey directly from the rawKey
		if pubKey, err = ssh.NewPublicKey(rawKey); err != nil {
			log.Fatalf("unable to create ssh.Signer or ssh.PublicKey from %T", rawKey)
		}
	}

	return pubKey
}

