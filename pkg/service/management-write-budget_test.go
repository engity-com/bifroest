package service

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/stretchr/testify/require"
)

type managementWriteBudgetResponse struct {
	http.ResponseWriter
	mutex                       sync.Mutex
	deadline                    time.Time
	cleared, written, unbounded bool
}

func (w *managementWriteBudgetResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *managementWriteBudgetResponse) SetWriteDeadline(at time.Time) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.deadline = at
	w.cleared = w.cleared || at.IsZero()
	return nil
}
func (w *managementWriteBudgetResponse) Write(data []byte) (int, error) {
	w.mutex.Lock()
	w.written = true
	w.unbounded = w.unbounded || w.deadline.IsZero() || !w.deadline.After(time.Now())
	w.mutex.Unlock()
	return w.ResponseWriter.Write(data)
}

func TestLongManagementReadsRestoreBoundedNetworkWritesOnFailure(t *testing.T) {
	_, handler, _, token := managementWebFixture(t, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V.(*configuration.EnvironmentManagement).AllowArtifactTransfer = true
	})
	for _, route := range []string{"recordings/verify", "audit-events/list", "artifacts/audit"} {
		t.Run(route, func(t *testing.T) {
			var observed *managementWriteBudgetResponse
			wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				observed = &managementWriteBudgetResponse{ResponseWriter: w}
				handler.ServeHTTP(observed, r)
			})
			reply := webTestRequest(wrapped, "POST", "app.example.org", webAPI+"management/"+route, `{"slug":"Work","auditlog":"missing"}`, token)
			require.Equal(t, http.StatusServiceUnavailable, reply.Code, reply.Body.String())
			require.NotNil(t, observed)
			observed.mutex.Lock()
			defer observed.mutex.Unlock()
			require.True(t, observed.cleared, "work has no inherited total write deadline")
			require.True(t, observed.written)
			require.False(t, observed.unbounded, "failed work must still have a bounded error-response write")
		})
	}
}
