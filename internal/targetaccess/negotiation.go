package targetaccess

import (
	"errors"
	"fmt"
	"strings"
)

type Hello struct {
	ContractVersions []string     `json:"contract_versions"`
	ProtocolVersions []string     `json:"protocol_versions"`
	Node             NodeIdentity `json:"node"`
}

type Negotiated struct {
	ContractVersion string       `json:"contract_version"`
	ProtocolVersion string       `json:"protocol_version"`
	Node            NodeIdentity `json:"node"`
}

func Negotiate(local, remote Hello) (Negotiated, error) {
	if err := local.Node.Validate(); err != nil {
		return Negotiated{}, fmt.Errorf("local node identity: %w", err)
	}
	if err := remote.Node.Validate(); err != nil {
		return Negotiated{}, fmt.Errorf("remote node identity: %w", err)
	}
	contract, ok := firstCommon(local.ContractVersions, remote.ContractVersions, []string{ContractVersion})
	if !ok {
		return Negotiated{}, errors.New("no compatible target-access contract version")
	}
	protocol, ok := firstCommon(local.ProtocolVersions, remote.ProtocolVersions, []string{ProtocolVersion})
	if !ok {
		return Negotiated{}, errors.New("no compatible target-access protocol version")
	}
	return Negotiated{
		ContractVersion: contract,
		ProtocolVersion: protocol,
		Node:            remote.Node,
	}, nil
}

func firstCommon(local, remote, supported []string) (string, bool) {
	remoteSet := map[string]struct{}{}
	for _, value := range remote {
		remoteSet[strings.TrimSpace(value)] = struct{}{}
	}
	localSet := map[string]struct{}{}
	for _, value := range local {
		localSet[strings.TrimSpace(value)] = struct{}{}
	}
	for _, value := range supported {
		if _, ok := localSet[value]; !ok {
			continue
		}
		if _, ok := remoteSet[value]; ok {
			return value, true
		}
	}
	return "", false
}
