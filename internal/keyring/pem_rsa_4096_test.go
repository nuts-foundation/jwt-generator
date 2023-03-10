package keyring

import (
	"testing"
)

func TestPEMRSA4096(t *testing.T) {
	testCase := &pemKeyTest{
		privateKey: `-----BEGIN PRIVATE KEY-----
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
t+5lDA37R/T7tu/dQaz79cwYOEA/gg==
-----END PRIVATE KEY-----`,

		publicKey: `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApqgTNAC1BRkG88FPLhiv
xfIB7zr0BJ1QTGMeifzGzSOTUzmw2ccOLQTL9ERhC5PTqNsAT8GjLmSS83Ma7osW
VGTqn0EDEx9TgTh30skOjERf9kJ/C/IbYRe7Qlps2mwhkYePZyOYuwwlsxsnnM21
EwTGOCcf1W9Xuz4Ut9ypS9pYpA7S3hw7cqZ0v4yURZDoLuroraqjHhGiAiAL3H1V
YP+GfVOWhPTmRiVdcqzLAewzJHxUaKdQqwevkmxGd0MbYYio3T4sIdsD2Epnmih6
s+XPW825F/H4sJKJ4xBjTjykn/0hGCkdyuR2vokK6dkTPJxeGlWasdeA+4SFGjt5
ibgCsh93mYIIQXBwsWcgzLMiATPNxO71Dj3GQWKBWikzUpIS5Ma7ua1hZYNyMK4n
2Cj5ngH8sDrQx4mI+Fc4xz65PRLDSmhWhSiVK8CiPoxpHR9tV93LLldWPr5rDob4
VsKQDcw0u+8/AqZyHxV5XqIA9qkfNXbf7Eg76gIc4jnXZ3mK3mhAMh/gL1NfnDaL
KD3lgxpdQ0FLccg0VsArkbT8pgP1naMM5ErixbzIAblkYWhN4BgJJ1I99ooY+TGu
Guqy0j2RPAYBI2KxVEWH4lBYaKo3kgq/Z1jxm2ATADD4PHvu+7dw0np8F4xeLhsY
a6AsNB6nuAsNUsMyrTu3rEsCAwEAAQ==
-----END PUBLIC KEY-----`,

		keyTest: keyTest{
			jwaSignatureAlgorithm: "PS512",

			jwkThumbprintSHA256:  "jdgiY4jHTqGA5TD3WsuOkW4pUODghTuAQlwXOJ0BQcM",
			sshFingerprintSHA256: "SHA256:O6Lq2n+tZIl4iaNW3DLxa0CC8392Gi1HLD+M7xbzSrQ",
		},
	}

	testCase.run(t)
}
