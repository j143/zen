package policy

import (
    "context"
    "sync"
    "time"

    "go.uber.org/zap"
)

const maxAllowedEpochDrift = 2

type ZENReport struct {
    ZENID        string
    TenantID     string
    AppliedEpoch int64
    ReportedAt   time.Time
}

type Reconciler struct {
    store    *Store
    reports  sync.Map   // ZENID → ZENReport
    logger   *zap.Logger
    pushFn   func(ctx context.Context, zenID string, changes []PolicyChange) error
}

func NewReconciler(store *Store, logger *zap.Logger,
    pushFn func(ctx context.Context, zenID string, changes []PolicyChange) error) *Reconciler {
    return &Reconciler{store: store, logger: logger, pushFn: pushFn}
}

func (r *Reconciler) UpdateReport(report ZENReport) {
    r.reports.Store(report.ZENID, report)
}

func (r *Reconciler) Run(ctx context.Context) {
    ticker := time.NewTicker(15 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            r.reconcile(ctx)
        case <-ctx.Done():
            return
        }
    }
}

func (r *Reconciler) reconcile(ctx context.Context) {
    r.reports.Range(func(key, val any) bool {
        report := val.(ZENReport)
        currentEpoch, err := r.store.CurrentEpoch(report.TenantID)
        if err != nil {
            r.logger.Error("epoch fetch failed", zap.String("zen", report.ZENID), zap.Error(err))
            return true
        }
        drift := currentEpoch - report.AppliedEpoch
        if drift > maxAllowedEpochDrift {
            r.logger.Warn("ZEN epoch drift detected",
                zap.String("zen", report.ZENID),
                zap.Int64("drift", drift),
                zap.Int64("current_epoch", currentEpoch),
                zap.Int64("zen_epoch", report.AppliedEpoch),
            )
            delta, err := r.store.Delta(report.TenantID, report.AppliedEpoch, currentEpoch)
            if err != nil {
                r.logger.Error("delta fetch failed", zap.String("zen", report.ZENID), zap.Error(err))
                return true
            }
            go func(zenID string, changes []PolicyChange) {
                if err := r.pushFn(ctx, zenID, changes); err != nil {
                    r.logger.Error("push failed", zap.String("zen", zenID), zap.Error(err))
                }
            }(report.ZENID, delta)
        }
        return true
    })
}

// Reports returns a snapshot of known ZEN reports.
func (r *Reconciler) Reports() []ZENReport {
    var out []ZENReport
    r.reports.Range(func(key, val any) bool {
        out = append(out, val.(ZENReport))
        return true
    })
    return out
}
