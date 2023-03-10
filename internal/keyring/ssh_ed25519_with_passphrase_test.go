package keyring

import (
	"testing"
)

func TestSSHEd25519WithPassphrase(t *testing.T) {
	testCase := &sshKeyTest{
		privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDX65ft4S
aaHT4NOKrHZKItAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIMmJXuzko4fxSglB
aKn84TIfBtsM+6vuJIMx41FVyFFAAAAAsGai/WykaHe93SaFlpvYFBXo6PcwF4xX8wGTD8
aj2WSKNjP/t7EDD0BgvKS62umizBYkw8a4kfTEQlA7iYMv09ZGMeUNIu/HeMxoJ6i+N26n
ZwoMur5xWaxYt9YBz8Cl/VEaqCRnbbTYK5DfxlrpTH/tdovXGgHf8aUrTWV/+z2JVmFzB9
we8BRjXVF+Y1eiKI/VQiqocTmFuBCBzcR4AeD7VXok5x+7DkfF6Og/RnAj
-----END OPENSSH PRIVATE KEY-----`,

		publicKey: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMmJXuzko4fxSglBaKn84TIfBtsM+6vuJIMx41FVyFFA`,

		passphrase: `supersecret`,

		keyTest: keyTest{
			jwaSignatureAlgorithm: "EdDSA",

			jwkThumbprintSHA256:  "-Dc1wrB8PSgSRT6TbVmfefhJksUdehth2vblt0JgECA",
			sshFingerprintSHA256: "SHA256:qBX6GEmlLeL17NLRhDx5IACwVhuY9z1Go7HGfjJW9Po",

			// TODO: The comment is not parsed for passphrase protected keys
			//comment: "ed25519-passphrase@example.com",
		},
	}

	testCase.run(t)
}
