package targetaccess

import "time"

// OpenSession installs the same current-trust verifier used by its TLS
// handshake. Trust removal and revocation also retire idle/active sessions.
func (s *Session) watchPeerTrust() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	defer s.Close()
	for {
		select {
		case <-s.lifetime.Done():
			return
		case <-ticker.C:
			if s.revalidatePeer() != nil {
				return
			}
		}
	}
}

func (s *Session) revalidatePeer() error {
	if s.checkTrust == nil {
		// Only package-local frame tests construct sessions without OpenSession.
		return nil
	}
	if err := s.checkTrust(); err != nil {
		_ = s.Close()
		return err
	}
	return nil
}
