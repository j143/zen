package auth

import (
    "fmt"
    "net/http"
    "strconv"
    "time"
)

// ObfuscateAPIKey implements the ZIA legacy API key obfuscation algorithm.
// Reference: https://help.zscaler.com/legacy-apis/api-authentication
// The password sent to POST /api/v1/authenticatedSession is NOT the raw key.
func ObfuscateAPIKey(apiKey string, nowMs int64) (string, error) {
    if len(apiKey) < 12 {
        return "", fmt.Errorf("apiKey too short: need >= 12 chars, got %d", len(apiKey))
    }
    ts := strconv.FormatInt(nowMs, 10)
    tsLen := len(ts)

    result := make([]byte, 0, 12)

    // First 6 chars: each char shifted by last digit of timestamp
    lastDigit := int(ts[tsLen-1] - '0')
    for i := 0; i < 6; i++ {
        result = append(result, apiKey[i]+byte(lastDigit))
    }

    // Next 6 chars: indexed via timestamp digits into apiKey
    for i := tsLen - 6; i < tsLen; i++ {
        idx := int(ts[i]-'0') + 2
        if idx >= len(apiKey) {
            return "", fmt.Errorf("timestamp digit index %d out of range for apiKey len %d", idx, len(apiKey))
        }
        result = append(result, apiKey[idx])
    }
    return string(result), nil
}

// ClockDriftError is returned when the server's Date header is >30s from local time.
type ClockDriftError struct {
    ServerTime time.Time
    LocalTime  time.Time
    DriftMs    int64
}

func (e *ClockDriftError) Error() string {
    return fmt.Sprintf("clock drift: %dms (server=%s, local=%s)",
        e.DriftMs, e.ServerTime.Format(time.RFC3339), e.LocalTime.Format(time.RFC3339))
}

func CheckClockDrift(serverDate string) error {
    st, err := http.ParseTime(serverDate)
    if err != nil {
        return nil // can't parse, skip check
    }
    local := time.Now()
    driftMs := local.Sub(st).Milliseconds()
    if driftMs < 0 {
        driftMs = -driftMs
    }
    const maxDriftMs = 30_000
    if driftMs > maxDriftMs {
        return &ClockDriftError{ServerTime: st, LocalTime: local, DriftMs: driftMs}
    }
    return nil
}
