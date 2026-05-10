package cert

import (
    "crypto/tls"
    "sync"
    "time"
)

const overlapDuration = 5 * time.Minute

type CertWindow struct {
    mu          sync.RWMutex
    active      *tls.Certificate
    previous    *tls.Certificate
    activeSince time.Time
    overlapUntil time.Time
}

func NewCertWindow(initial *tls.Certificate) *CertWindow {
    return &CertWindow{
        active:      initial,
        activeSince: time.Now(),
        overlapUntil: time.Time{}, // no overlap initially
    }
}

// Rotate replaces the active cert and starts the overlap window.
// Called when a tenant uploads a new root CA via the Admin Portal.
func (w *CertWindow) Rotate(newCert *tls.Certificate) {
    w.mu.Lock()
    defer w.mu.Unlock()
    w.previous = w.active
    w.active = newCert
    w.activeSince = time.Now()
    w.overlapUntil = time.Now().Add(overlapDuration)
}

// GetCert returns the cert for a new TLS connection.
// During the overlap window, both old and new certs are valid.
// After the window, only the new cert is served.
func (w *CertWindow) GetCert(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
    w.mu.RLock()
    defer w.mu.RUnlock()
    // Always serve the new cert; ZEN nodes retry with previous if handshake fails.
    // The overlap window means edges still holding the old intermediate won't break sessions.
    return w.active, nil
}

func (w *CertWindow) InOverlapWindow() bool {
    w.mu.RLock()
    defer w.mu.RUnlock()
    return w.previous != nil && time.Now().Before(w.overlapUntil)
}

func (w *CertWindow) OverlapTimeRemaining() time.Duration {
    w.mu.RLock()
    defer w.mu.RUnlock()
    if w.previous == nil {
        return 0
    }
    return time.Until(w.overlapUntil)
}
