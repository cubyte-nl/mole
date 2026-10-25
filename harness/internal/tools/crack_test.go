package tools

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCrackRegistryGating(t *testing.T) {
	s := testScope("127.0.0.1")
	// A reconnaissance engagement cannot reach crack at all.
	if res := NewRegistry(false, newLedger(t), newKB()).Run(testCtx, s, "crack", `{"hash":"x","source":"127.0.0.1"}`); res.Allowed {
		t.Error("crack reachable in a reconnaissance registry")
	}
	if !registered(NewRegistry(true, newLedger(t), newKB()), "crack") {
		t.Error("crack not registered in a vuln-scanning registry")
	}
}

func TestCrackGate(t *testing.T) {
	s := testScope("127.0.0.1")

	// Missing hash is denied before anything else.
	if res := (Crack{}).Run(testCtx, s, map[string]any{"source": "127.0.0.1"}); res.Allowed {
		t.Error("missing hash was allowed")
	}

	// Missing source (the scope anchor) is denied.
	if res := (Crack{}).Run(testCtx, s, map[string]any{"hash": "e10adc3949ba59abbe56e057f20f883e"}); res.Allowed {
		t.Error("missing source was allowed")
	}

	// Out-of-scope source is gate-denied, even with a perfectly valid hash.
	if res := (Crack{}).Run(testCtx, s, map[string]any{
		"hash":   "e10adc3949ba59abbe56e057f20f883e",
		"source": "definitely-not-a-host.invalid",
	}); res.Allowed {
		t.Errorf("out-of-scope source was allowed: %s", res.Reason)
	}

	// An undetectable hash format asks for an explicit mode instead of
	// guessing.
	res := (Crack{}).Run(testCtx, s, map[string]any{
		"hash":   "definitely-not-a-real-hash-format",
		"source": "127.0.0.1",
	})
	if res.Allowed {
		t.Errorf("undetectable hash format was allowed: %s", res.Reason)
	}
	if !strings.Contains(res.Reason, "mode") {
		t.Errorf("denial should ask for an explicit mode: %s", res.Reason)
	}
}

func TestDetectHashMode(t *testing.T) {
	cases := []struct {
		hash string
		want int
	}{
		{"e10adc3949ba59abbe56e057f20f883e", 100},                                 // 32-hex → NTLM
		{"aad3b435b51404eeaad3b435b51404ee", 3000},                                // 32-hex, trailing 16 zeros → LM
		{"5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", 300},                         // 40-hex → SHA1
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 400}, // 64-hex → SHA256
		{"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", 600}, // 128-hex → SHA512
		{"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", 7400},                                                                    // bcrypt
		{"$2b$12$WApznuph05jeVHXCMLY1feqM1OlY5LjY0xkYJdLWY0xkYJdLWY0xk", 7400},                                                                    // bcrypt (2b)
		{"$6$saltsalt$QrZkVHfYqW1xZm8sKpL5nV0jT3cD7eA9bG1hJ2kL3mN4oP5qR6sT7uV8wX9yZ0aB1cD2eF3gH4iJ5kL6mN7o", 7500},                                // sha512crypt
		{"$5$saltsalt$QrZkVHfYqW1xZm8sKpL5nV0jT3cD7eA9bG1hJ2kL3mN4oP5qR6sT7uV8wX9yZ0aB1cD2eF3gH4iJ5kL6mN7o", 1800},                                // sha256crypt
		{"$1$saltsalt$QrZkVHfYqW1xZm8sKpL5nV0jT3cD7eA9bG1hJ2kL3mN4oP5qR6sT7uV8wX9", 5000},                                                         // md5crypt
		{"not-a-hash", -1},
		{"", -1},
	}
	for _, c := range cases {
		if got := detectHashMode(c.hash); got != c.want {
			t.Errorf("detectHashMode(%q) = %d, want %d", c.hash, got, c.want)
		}
	}
}

func TestCrackRealRun(t *testing.T) {
	if _, err := exec.LookPath("hashcat"); err != nil {
		t.Skip("hashcat not installed")
	}
	wordlist := "../../data/wordlists/top1000.txt"
	if _, err := os.Stat(wordlist); err != nil {
		t.Skipf("bundled wordlist not present: %v", err)
	}
	s := testScope("127.0.0.1")
	// MD5 of "123456", which is in the bundled top-1000 wordlist. Pass mode
	// 0 explicitly (32-hex would auto-detect as NTLM).
	res := (Crack{}).Run(testCtx, s, map[string]any{
		"hash":     "e10adc3949ba59abbe56e057f20f883e",
		"source":   "127.0.0.1",
		"mode":     0,
		"wordlist": wordlist,
		"timeout":  30,
	})
	if !res.Allowed {
		t.Fatalf("crack denied: %s", res.Reason)
	}
	pl := res.Payload.(map[string]any)
	if pl["cracked"] != true {
		t.Fatalf("expected the MD5 hash to crack, got cracked=%v (output: %s)", pl["cracked"], pl["output"])
	}
	if pw, _ := pl["password"].(string); pw != "123456" {
		t.Errorf("password = %q, want 123456", pw)
	}
	if pl["mode_name"] != "MD5" {
		t.Errorf("mode_name = %v, want MD5", pl["mode_name"])
	}
}
