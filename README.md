# nuts-jwt-generator
nuts-jwt-generator is a utility for generating tokens to authenticate to token_v2 protected nuts-node APIs. The tokens are compact encoded JWTs (JSON Web Tokens) which are signed by a known cryptography key. The keys permitted to create valid tokens are configured on the nuts node.

## Installing
To install the tool download a binary from the github releases page.

On a MacOS/Linux system you can copy/paste the URL of the binary, replacing $BINARY_URL in the following command:
```
curl --fail -L -o /usr/local/bin/nuts-jwt-generator $BINARY_URL
chmod +x /usr/local/bin/nuts-jwt-generator
```

## Supported Keys
The following key algorithms are supported:
- Ed25519
- ECDSA P-256, P-384, P-521
- RSA 2048-bit, 3072-bit, 4096-bit

The following key file formats are supported:
- OpenSSH
- JWK
- PEM

### Key Generation (OpenSSH)
To generate an Ed25519 key:
```
ssh-keygen -t ed25519 -f <path-to-key>
```

To generate an ECDSA key:
```
ssh-keygen -t ecdsa -b 521 -f <path-to-key>
```

To generate an RSA key:
```
ssh-keygen -t rsa -b 4096 -f <path-to-key>
```

### Key Generation (PEM)
To generate an Ed25519 key:
```
openssl genpkey -algorithm ed25519 -out <path-to-private-pem>
openssl pkey -in <path-to-private-pem> -pubout -out <path-to-public-pem>
```

To generate an ECDSA key:
```
TODO
```

To generate an RSA key:
```
TODO
```

## Usage

### To create a JWT using an SSH private key file
```
nuts-jwt-generator -i ~/.ssh/id_nutsapi --host nuts-server-001
```

### To create a JWT using a key loaded in ssh-agent
```
nuts-jwt-generator -i ~/.ssh/id_agentkey.pub --host nuts-server-001
```

### To create a JWT using a PEM private key file
```
nuts-jwt-generator -i ~/.nuts/apikey.pem --host nuts-server-001
```

### To create a JWT using a JWK private key file
```
nuts-jwt-generator -i ~/.nuts/apikey.jwk --host nuts-server-001
```

### Generating the SSH SHA256 Fingerprint of a Key
```
nuts-jwt-generator -i <path-to-key> --export-ssh-fingerprint
```

### Generating the JWK Thumbprint of a Key
```
nuts-jwt-generator -i <path-to-key> --export-jwk-thumbprint
```

### Generating the SSH authorized_keys Form of a Key
```
nuts-jwt-generator -i <path-to-key> --export-authorized-key
```

### Command Line Flags
```
Usage of nuts-jwt-generator:
  -duration int
        duration in seconds of the token validity (default 300)
  -export-authorized-key
        Export the authorized_keys format
  -export-jwk-thumbprint
        Export the JWK SHA256 thumbprint
  -export-ssh-fingerprint
        Export the SSH SHA256 fingerprint
  -host string
        hostname of nuts node, for aud field of JWT
  -i string
        key file path (private for internal signing, public for ssh-agent signing)
  -list-agent
        list SSH keys from ssh-agent
  -quiet
        disable logging output
  -user string
        username (default: key comment or current username/hostname)
```

## Development

### Building
To build the tool locally checkout the repo and run:
```
make build
```

### Building a release
To build a release for all supported architectures:
```
make release
```
