package service

import (
	"errors"

	"github.com/gorilla/websocket"
)

func (s *webTerminalStream) monitoringFailure(err error) {
	if err == nil {
		s.monitoringEnd.CompareAndSwap(0, 4)
		return
	}
	reason := monitoringEndReason(err)
	var closeError *websocket.CloseError
	if errors.As(err, &closeError) && (closeError.Code == websocket.CloseNormalClosure || closeError.Code == websocket.CloseGoingAway) {
		reason = 2
	}
	s.monitoringEnd.CompareAndSwap(0, reason)
}

func (s *webTerminalStream) monitoringReason() string {
	switch s.monitoringEnd.Load() {
	case 5:
		return "authentication_denied"
	case 6:
		return "connection_denied"
	case 7:
		return "error"
	case 8:
		return "shutdown"
	case 9:
		return "completed"
	default:
		return monitoringCloseReason(s.monitoringEnd.Load())
	}
}
