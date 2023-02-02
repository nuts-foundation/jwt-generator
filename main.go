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
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type signingFunc func([]byte) (*ssh.Signature, error)

// store the command line arguments in a global struct
var arguments struct {
	duration int
	host string

	agentKey string
	keyFilePath string

	listKeys bool
	verbose bool
}

// init sets up the command line arguments
func init() {
	flag.StringVar(&arguments.host, "host", "", "hostname of nuts node")
	flag.StringVar(&arguments.agentKey, "key", "", "SSH agent key specification")
	flag.StringVar(&arguments.keyFilePath, "i", "", "SSH key file path")
	flag.BoolVar(&arguments.listKeys, "list", false, "list SSH keys from ssh-agent")
	flag.BoolVar(&arguments.verbose, "verbose", false, "enable logging output")
	flag.IntVar(&arguments.duration, "duration", 300, "duration in seconds of the token validity")
}

func main() {
	// Parse command line arguments
	flag.Parse()

	// Check command line syntax
	if !arguments.listKeys && arguments.host == "" {
		log.Fatal("syntax error: missing host argument")
	}
	
	// Disable logging unless --verbose was specified
	if !arguments.verbose {
		log.SetOutput(io.Discard)
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

		// Build the payload of the JWT using the command line arguments
		payload := buildPayload(arguments.host, arguments.duration, defaultKeyComment())

		// Setup the key file based signer
		signer := keyFileBasedSigningFunc(key)

		// Sign and print the token
		token := signPayload(signer, payload)
		fmt.Printf("%v\n", token)
	} else {
		// Connect to the ssh-agent
		agentClient := connectAgent()

		// Select the key for authenticating to the API
		key, err := selectSSHKey(agentClient, arguments.agentKey)
		if err != nil {
			log.Fatalf("failed to find ssh-agent key (%v): %v", arguments.agentKey, err)
		}

		// Build the payload of the JWT using the command line arguments
		payload := buildPayload(arguments.host, arguments.duration, key.Comment)

		// Setup the agent based signer
		signer := agentBasedSigningFunc(agentClient, key)

		// Sign and print the token
		token := signPayload(signer, payload)
		fmt.Printf("%v\n", token)
	}
}

// keyFileBasedSigningFunc takes an SSH private key (interface{} as it can be many types) and returns
// a signingFunc to be used for signing tokens
func keyFileBasedSigningFunc(key interface{}) signingFunc {
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		log.Fatalf("failed to create signer from key: %v", err)
	}

	return func(plaintext []byte) (*ssh.Signature, error) {
		return signer.Sign(rand.Reader, plaintext)
	}
}

func agentBasedSigningFunc(agentClient agent.Agent, key *agent.Key) signingFunc {
	return func(plaintext []byte) (*ssh.Signature, error) {
		return agentClient.Sign(key, plaintext)
	}
}

func parseKeyFile(path string) interface{} {
	// Read the key file
	contents, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("failed to read %v: %v", arguments.keyFilePath, err)
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

func signPayload(signer signingFunc, payload []byte) string {
	// Sign the JWT
	signature, err := signer(payload)
	if err != nil {
		log.Fatalf("failed to sign: %v", err)
	}

	// Build the JWT headers
	headers := make(map[string]string)
	headers["typ"] = "JWT"
	headers["alg"] = jwtAlgFromSSHSignature(signature)
	serializedHeaders, err := json.Marshal(headers)
	if err != nil {
		log.Fatalf("failed to serialize headers: %v", err)
	}
	log.Printf("headers: %+v", headers)

	log.Printf("signed: %+v", signature)
	
	// Encode the JWT
	encodedJWT := assembleJWT(serializedHeaders, payload, signature.Blob)
	return encodedJWT
}

// connectAgent returns a connected client for the ssh-agent
func connectAgent() agent.Agent {
	// ssh-agent(1) provides a UNIX socket at $SSH_AUTH_SOCK.
	socket := os.Getenv("SSH_AUTH_SOCK")
	connection, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}

	return agent.NewClient(connection)
}

// assembleJWT builds the final JWT from its components
func assembleJWT(serializedHeaders []byte, serializedToken []byte, signature []byte) string {
	b64Headers := b64.RawStdEncoding.EncodeToString(serializedHeaders)
	b64Token := b64.RawStdEncoding.EncodeToString(serializedToken)
	b64Signature := b64.RawStdEncoding.EncodeToString(signature)
	return strings.Join([]string{b64Headers, b64Token, b64Signature}, ".")
}

// jwtAlgFromSSHSignature returns the JWT signature algorithm that corresponds to the given SSH signature format
func jwtAlgFromSSHSignature(signature *ssh.Signature) string {
	switch signature.Format {
	case "ecdsa-sha2-nistp256":
		return "ES256"
	case "ecdsa-sha2-nistp384":
		return "ES384"
	case "ecdsa-sha2-nistp512":
		return "ES512"
	case "ssh-ed25519":
		return "EdDSA"
	default:
		log.Fatalf("unsupported signature format: (%v) %+v", len(signature.Blob), signature)
	}

	// This point should be unreachable due to the default case above
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
