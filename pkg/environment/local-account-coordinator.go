package environment

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/engity-com/bifroest/pkg/session"
)

type localAccountCoordinator struct {
	mu       sync.Mutex
	sessions session.Repository
}

func localSessionHasActiveConnections(sess session.Session) bool {
	connections, ok := sess.(interface{ HasActiveConnections() bool })
	return !ok || connections.HasActiveConnections()
}

// otherActive checks all flows while Ensure and Dispose share the coordinator
// lock. Unreadable sessions are an error, not evidence that the account is free.
func (this *localAccountCoordinator) otherActive(ctx context.Context, current session.Session, name, identity string) (bool, error) {
	if this == nil || this.sessions == nil {
		return false, fmt.Errorf("cannot delete local account without a session repository")
	}
	active := false
	foundCurrent := false
	err := this.sessions.FindAll(ctx, func(ctx context.Context, other session.Session) (bool, error) {
		isCurrent := other.Flow() == current.Flow() && other.Id() == current.Id()
		encoded, err := other.EnvironmentToken(ctx)
		if err != nil {
			return false, err
		}
		if len(encoded) == 0 {
			if isCurrent {
				return false, fmt.Errorf("local account session %s/%s has no environment token", current.Flow(), current.Id())
			}
			return true, nil
		}
		var token struct {
			User struct {
				Name string          `json:"name"`
				UID  json.RawMessage `json:"uid"`
				SID  string          `json:"sid"`
			} `json:"user"`
		}
		if err := json.Unmarshal(encoded, &token); err != nil {
			return false, err
		}
		var uid string
		if len(token.User.UID) > 0 && string(token.User.UID) != "null" {
			if err := json.Unmarshal(token.User.UID, &uid); err != nil {
				var number uint32
				if err := json.Unmarshal(token.User.UID, &number); err != nil {
					return false, fmt.Errorf("invalid local account UID in session %s: %w", other.Id(), err)
				}
				uid = fmt.Sprint(number)
			}
		}
		nameMatches := token.User.Name != "" && strings.EqualFold(token.User.Name, name)
		identityMatches := (token.User.SID != "" && token.User.SID == identity) ||
			(uid != "" && uid == identity)
		if isCurrent {
			if !nameMatches && !identityMatches {
				return false, fmt.Errorf("local account session %s/%s changed identity", current.Flow(), current.Id())
			}
			foundCurrent = true
			return true, nil
		}
		if !nameMatches && !identityMatches {
			return true, nil
		}
		info, err := other.Info(ctx)
		if err != nil {
			return false, err
		}
		if info.State() != session.StateDisposed {
			active = true
			return false, nil
		}
		if localSessionHasActiveConnections(other) {
			active = true
			return false, nil
		}
		return true, nil
	}, nil)
	if err == nil && !active && !foundCurrent {
		return false, fmt.Errorf("cannot confirm local account session %s/%s in session repository", current.Flow(), current.Id())
	}
	return active, err
}
