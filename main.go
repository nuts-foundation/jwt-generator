// A JWT generator for authenticating to nuts-node services
package main

import (
	b64 "encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
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

	// The uuid library is used to generate JWT IDs
	"github.com/google/uuid"

	"github.com/nuts-foundation/jwt-generator/internal/keyring"
)

const usage = `nuts-jwt-generator is a utility for generating tokens to authenticate
to token_v2 protected nuts-node APIs. The tokens are compact encoded
JWTs (JSON Web Tokens) which are signed by a known cryptography key
The keys permitted to create valid tokens are configured on the nuts
node.

To create a JWT using an SSH private key file:
nuts-jwt-generator -i ~/.ssh/id_nutsapi --host nuts-server-001

To create a JWT using a key loaded in ssh-agent:
nuts-jwt-generator -i ~/.ssh/id_agentkey.pub --host nuts-server-001

To create a JWT using a PEM private key file:
nuts-jwt-generator -i ~/.nuts/apikey.pem --host nuts-server-001

To create a JWT using a JWK private key file:
nuts-jwt-generator -i ~/.nuts/apikey.jwk --host nuts-server-001`

// store the command line arguments in a global struct
var arguments struct {
	duration int
	host     string
	user     string

	keyFilePath string

	exportAuthorizedKey  bool
	exportJWKThumbprint  bool
	exportSSHFingerprint bool
	listAgentKeys        bool

	quiet bool
}

// init sets up the command line arguments
func init() {
	flag.StringVar(&arguments.host, "host", "", "hostname of nuts node, for aud field of JWT")
	flag.StringVar(&arguments.user, "user", "", "username (default: key comment or current username/hostname)")
	flag.StringVar(&arguments.keyFilePath, "i", "", "key file path (private for internal signing, public for ssh-agent signing)")
	flag.BoolVar(&arguments.listAgentKeys, "list-agent", false, "list SSH keys from ssh-agent")
	flag.BoolVar(&arguments.quiet, "quiet", false, "disable logging output")
	flag.IntVar(&arguments.duration, "duration", 300, "duration in seconds of the token validity")
	flag.BoolVar(&arguments.exportAuthorizedKey, "export-authorized-key", false, "Export the authorized_keys format")
	flag.BoolVar(&arguments.exportJWKThumbprint, "export-jwk-thumbprint", false, "Export the JWK SHA256 thumbprint")
	flag.BoolVar(&arguments.exportSSHFingerprint, "export-ssh-fingerprint", false, "Export the SSH SHA256 fingerprint")

	// Show a summary of usage when -h/--help is passed
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintf(out, "%s\n", usage)
		fmt.Fprint(out, "\n")
		fmt.Fprint(out, "Usage of nuts-jwt-generator:\n")
		flag.PrintDefaults()
	}
}

func main() {
	// Parse command line arguments
	flag.Parse()

	// Disable logging if --quiet was specified
	if arguments.quiet {
		log.SetOutput(io.Discard)
	}

	// Optionally list the keys available in the ssh-agent
	if arguments.listAgentKeys {
		listSSHKeys(connectAgent())
		return
	}

	// Ensure a key file was provided, as the remaining program modes require it
	if arguments.keyFilePath == "" {
		log.Fatal("syntax error: missing -i (key file) argument")
	}

	// Load the key from the filesystem
	key := parseKeyFile(arguments.keyFilePath)

	// Optionally export the key in authorized_keys format
	if arguments.exportAuthorizedKey {
		exportAuthorizedKey(key)
		return
	}

	// Optionally export the key fingerprint in SSH SHA256 format
	if arguments.exportSSHFingerprint {
		exportSSHFingerprint(key)
		return
	}

	// Optionally export the key thumbprint in JWK SHA256 format
	if arguments.exportJWKThumbprint {
		exportJWKThumbprint(key)
		return
	}

	// Ensure a host argument was provided
	if arguments.host == "" {
		log.Fatal("syntax error: missing --host argument")
	}

	// Get the subject to sign JWTs for from key, the --user argument, or the user/hostnames
	subject := key.Comment()
	if subject == "" {
		if arguments.user != "" {
			subject = arguments.user
		} else {
			subject = defaultSubject()
		}
	}

	// Build the JWT using the command line arguments
	token := buildToken(arguments.host, arguments.duration, subject)

	// When provided a private key sign the JWT directly
	if key.IsPrivate() {
		signed, err := key.SignJWT(token)
		if err != nil {
			log.Fatalf("failed to sign JWT: %v", err)
		}

		// Print the generated JWT
		fmt.Printf("%s\n", signed)

	} else {
		// When provided a public key sign the JWT using the ssh-agent
		signed, err := key.SignJWTWithAgent(connectAgent(), token)
		if err != nil {
			log.Fatalf("failed to sign JWT with ssh-agent: %v", err)
		}

		// Print the generated JWT
		fmt.Printf("%s\n", signed)
	}
}

func parseKeyFile(path string) keyring.Key {
	// Parse the key file
	key, err := keyring.Open(path)
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
			key, err := keyring.OpenWithPassphrase(path, passphrase)

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

// buildToken returns a jwt.Token
func buildToken(host string, duration int, user string) jwt.Token {
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

	return token
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

// defaultSubject returns a string (user@host) based on the current username/hostname. This is
// to be used when a key comment is not available (the embedded comments in file based keys do
// not seem to be accessible via x/crypto/ssh -- so this is used for the time being).
func defaultSubject() string {
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

func exportAuthorizedKey(key keyring.Key) {
	// Convert the key to an ssh.PublicKey interface
	publicKey, err := key.SSHPublicKey()
	if err != nil {
		log.Fatalf("failed to convert to ssh.PublicKey: %v", err)
	}

	// Print the authorized_keys entry format for the given public key
	authorizedKey := ssh.MarshalAuthorizedKey(publicKey)
	fmt.Println(string(authorizedKey))
}

func exportSSHFingerprint(key keyring.Key) {
	// Generate and print the fingerprint
	fingerprint, err := key.SSHFingerprintSHA256()
	if err != nil {
		log.Fatalf("error generating fingerprint: %v", err)
	}
	fmt.Println(fingerprint)
}

func exportJWKThumbprint(key keyring.Key) {
	// Generate the thumbprint
	thumbprint, err := key.JWKThumbprintSHA256()
	if err != nil {
		log.Fatalf("error generating fingerprint: %v", err)
	}

	// Print the thumbprint
	fmt.Println(thumbprint)
}
