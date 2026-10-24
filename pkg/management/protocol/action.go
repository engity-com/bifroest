package protocol

import "time"

type SessionAction struct {
	Action string `json:"action"`
	Flow   string `json:"flow"`
	ID     string `json:"id"`
}

func (this SessionAction) Validate() error {
	if (this.Action != "disconnect" && this.Action != "dispose") || this.Flow == "" || !text(this.Flow, 255) || !ValidID(this.ID) {
		return ErrRequest
	}
	return nil
}

type SessionActionResult struct {
	ID     string `json:"id" yaml:"id"`
	Flow   string `json:"flow" yaml:"flow"`
	Action string `json:"action" yaml:"action"`
}

type ActionPreparation struct {
	Version           int         `json:"version"`
	Status            string      `json:"status"`
	ConfirmationToken string      `json:"confirmationToken"`
	ExpiresAt         time.Time   `json:"expiresAt"`
	Action            string      `json:"action"`
	Target            SessionItem `json:"target"`
}
type ActionResult struct {
	Version int                 `json:"version"`
	Status  string              `json:"status"`
	Result  SessionActionResult `json:"result"`
}
