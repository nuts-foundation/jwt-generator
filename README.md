# jwt-generator
A JWT generator for authenticating to nuts-node services

## Generating the SSH SHA256 Fingerprint of a Key
```
nuts-jwt-generator -i <path-to-key> --export-ssh-fingerprint
```

## Generating the JWK Thumbprint of a Key
```
nuts-jwt-generator -i <path-to-key> --export-jwk-thumbprint
```

## Generating the SSH authirozed_keys Form of a Key
```
nuts-jwt-generator -i <path-to-key> --export-authorized-key
```
