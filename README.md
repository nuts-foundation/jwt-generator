# nuts-jwt-generator
nuts-jwt-generator is a utility for generating tokens to authenticate to token_v2 protected nuts-node APIs. The tokens are compact encoded JWTs (JSON Web Tokens) which are signed by a known cryptography key. The keys permitted to create valid tokens are configured on the nuts node.

## Installing
To install the tool download a binary from the github releases page.

On a MacOS/Linux system you can copy/paste the URL of the binary, replacing $BINARY_URL in the following command:
```
curl -o /usr/local/bin/nuts-jwt-generator $BINARY_URL
chmod +x /usr/local/bin/nuts-jwt-generator
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
