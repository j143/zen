package main

import (
    "context"
    "crypto/tls"
    "database/sql"
    "encoding/json"
    "log"
    "net/http"
    "os"
    "strconv"
    "time"

    "github.com/redis/go-redis/v9"
    "github.com/j143/zen/internal/auth"
    "github.com/j143/zen/internal/cert"
    "github.com/j143/zen/internal/policy"
    "go.uber.org/zap"
)

func main() {
    logger, _ := zap.NewProduction()
    defer logger.Sync()

    dbURL := os.Getenv("DB_URL")
    if dbURL == "" {
        dbURL = "postgres://ca:ca_secret@localhost:5432/zia_ca?sslmode=disable"
    }
    redisAddr := os.Getenv("REDIS_ADDR")
    if redisAddr == "" {
        redisAddr = "localhost:6379"
    }

    db, err := sql.Open("postgres", dbURL)
    if err != nil {
        log.Fatalf("db open: %v", err)
    }
    db.SetConnMaxLifetime(time.Minute * 5)

    rdb := redis.NewClient(&redis.Options{Addr: redisAddr})

    store := policy.NewStore(db)
    samlCache := auth.NewSAMLCache(rdb, 0)
    certWindow := cert.NewCertWindow(nil)

    pushFn := func(ctx context.Context, zenID string, changes []policy.PolicyChange) error {
        logger.Info("push simulated", zap.String("zen", zenID), zap.Int("changes", len(changes)))
        return nil
    }

    reconciler := policy.NewReconciler(store, logger, pushFn)

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    go reconciler.Run(ctx)

    mux := http.NewServeMux()

    mux.HandleFunc("/api/v1/auth/saml", func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case http.MethodPost:
            var req struct {
                NameID      string   `json:"name_id"`
                SessionIdx  string   `json:"session_idx"`
                UserID      string   `json:"user_id"`
                Groups      []string `json:"groups"`
                PolicyEpoch int64    `json:"policy_epoch"`
                ExpiresInSec int64   `json:"expires_in_sec"`
                IdPEntityID string   `json:"idp_entity_id"`
            }
            if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                http.Error(w, err.Error(), http.StatusBadRequest)
                return
            }
            sess := auth.SAMLSession{
                UserID: req.UserID,
                Groups: req.Groups,
                PolicyEpoch: req.PolicyEpoch,
                ExpiresAt: time.Now().Add(time.Duration(req.ExpiresInSec) * time.Second),
                IdPEntityID: req.IdPEntityID,
            }
            if err := samlCache.Set(r.Context(), req.NameID, req.SessionIdx, sess); err != nil {
                http.Error(w, err.Error(), http.StatusInternalServerError)
                return
            }
            w.WriteHeader(http.StatusNoContent)
        case http.MethodGet:
            q := r.URL.Query()
            nameID := q.Get("name_id")
            sessionIdx := q.Get("session_idx")
            idp := q.Get("idp_entity_id")
            if nameID == "" || sessionIdx == "" {
                http.Error(w, "missing params", http.StatusBadRequest)
                return
            }
            sess, ok := samlCache.Get(r.Context(), nameID, sessionIdx, idp)
            if !ok {
                http.Error(w, "not found", http.StatusNotFound)
                return
            }
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(sess)
        case http.MethodDelete:
            // support DELETE /api/v1/auth/saml?name_id=...&session_idx=...&idp_entity_id=...
            q := r.URL.Query()
            nameID := q.Get("name_id")
            sessionIdx := q.Get("session_idx")
            idp := q.Get("idp_entity_id")
            if nameID == "" || sessionIdx == "" {
                http.Error(w, "missing params", http.StatusBadRequest)
                return
            }
            // For simplicity, just call Get and then InvalidateUser if found
            if sess, ok := samlCache.Get(r.Context(), nameID, sessionIdx, idp); ok {
                samlCache.InvalidateUser(r.Context(), sess.UserID)
            }
            w.WriteHeader(http.StatusNoContent)
        default:
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        }
    })

    mux.HandleFunc("/api/v1/users/", func(w http.ResponseWriter, r *http.Request) {
        // DELETE /api/v1/users/{id}
        if r.Method != http.MethodDelete {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        id := r.URL.Path[len("/api/v1/users/"):]
        if id == "" {
            http.Error(w, "missing id", http.StatusBadRequest)
            return
        }
        if err := samlCache.InvalidateUser(r.Context(), id); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusNoContent)
    })

    mux.HandleFunc("/api/v1/policy/change", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        var req struct {
            TenantID   string          `json:"tenant_id"`
            ChangeType string          `json:"change_type"`
            Payload    json.RawMessage `json:"payload"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        epoch, err := store.AppendChange(req.TenantID, req.ChangeType, []byte(req.Payload))
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]any{"epoch": epoch})
    })

    mux.HandleFunc("/api/v1/policy/delta", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        q := r.URL.Query()
        tenant := q.Get("tenant_id")
        fromS := q.Get("from")
        toS := q.Get("to")
        if tenant == "" || fromS == "" || toS == "" {
            http.Error(w, "missing params", http.StatusBadRequest)
            return
        }
        from, _ := strconv.ParseInt(fromS, 10, 64)
        to, _ := strconv.ParseInt(toS, 10, 64)
        changes, err := store.Delta(tenant, from, to)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(changes)
    })

    mux.HandleFunc("/api/v1/zen/report", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        var req struct {
            ZENID        string `json:"zen_id"`
            TenantID     string `json:"tenant_id"`
            AppliedEpoch int64  `json:"applied_epoch"`
        }
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        reconciler.UpdateReport(policy.ZENReport{ZENID: req.ZENID, TenantID: req.TenantID, AppliedEpoch: req.AppliedEpoch, ReportedAt: time.Now()})
        w.WriteHeader(http.StatusNoContent)
    })

    mux.HandleFunc("/api/v1/zen/status", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        reports := reconciler.Reports()
        type outT struct {
            policy.ZENReport
            CurrentEpoch int64 `json:"current_epoch"`
            Drift        int64 `json:"drift"`
        }
        var out []outT
        for _, rep := range reports {
            cur, _ := store.CurrentEpoch(rep.TenantID)
            out = append(out, outT{ZENReport: rep, CurrentEpoch: cur, Drift: cur - rep.AppliedEpoch})
        }
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(out)
    })

    mux.HandleFunc("/api/v1/cert/rotate", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        // For demo, create an empty cert and rotate
        newCert := &tls.Certificate{}
        certWindow.Rotate(newCert)
        // append a policy change to indicate rotation (optional)
        store.AppendChange("global", "cert_rotation", []byte(`{"note":"rotated"}`))
        w.WriteHeader(http.StatusNoContent)
    })

    mux.HandleFunc("/api/v1/cert/overlap", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }
        rem := certWindow.OverlapTimeRemaining()
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]any{"overlap_seconds": int64(rem.Seconds())})
    })

    addr := ":8080"
    logger.Info("starting server", zap.String("addr", addr))
    if err := http.ListenAndServe(addr, mux); err != nil {
        logger.Fatal("server failed", zap.Error(err))
    }
}
