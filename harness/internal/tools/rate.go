package tools

import (
	"context"
	"sync"
	"time"
)

// webRate caps how fast the web validation tools (web_check, http_request)
// may request a single host: 10 requests/second. The limit lives in code, not
// in the prompt — the model cannot ask its way out of it.
const webRate = 10

// rateLimiter is a per-host token bucket. Each host gets a full bucket on
// first use; tokens refill at rate/second up to the bucket capacity (rate),
// so bursts of up to `rate` requests pass instantly and sustained traffic
// settles at rate/second per host.
type rateLimiter struct {
	rate   float64
	mu     sync.Mutex
	tokens map[string]float64
	last   map[string]time.Time
}

func newRateLimiter(rate float64) *rateLimiter {
	return &rateLimiter{rate: rate, tokens: map[string]float64{}, last: map[string]time.Time{}}
}

// Wait blocks until a token is available for host, honouring ctx. It returns
// ctx.Err() when the context is done.
func (rl *rateLimiter) Wait(ctx context.Context, host string) error {
	for {
		rl.mu.Lock()
		now := time.Now()
		tok, seen := rl.tokens[host]
		if !seen {
			tok = rl.rate // first use for this host: full bucket
		}
		tok += now.Sub(rl.last[host]).Seconds() * rl.rate
		if tok > rl.rate {
			tok = rl.rate
		}
		if tok >= 1 {
			tok--
			rl.tokens[host] = tok
			rl.last[host] = now
			rl.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - tok) / rl.rate * float64(time.Second))
		rl.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// webLimiter is the shared per-host rate cap for the web validation tools.
var webLimiter = newRateLimiter(webRate)
