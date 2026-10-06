package targetaccess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrAdmissionJournal = errors.New("protected transport admission is unavailable")
var ErrReplayConflict = errors.New("request identifier was admitted with different content")
var ErrReplayAmbiguous = errors.New("request identifier was already admitted; reconcile observed state")

const maxAdmissionRecords = 8192
const maxAdmissionRecordBytes = 2048

// AdmissionJournal retains transport admission only, never desired state,
// credentials, argv, artifact bytes, execution results or provider errors.
// Every side effect must persist admission before execution. Existing records
// are never automatically removed, retried or changed back to unadmitted.
type AdmissionJournal struct {
	mu          sync.Mutex
	root        *os.Root
	scope       NodeIdentity
	scopeDigest string
	maxRecords  int
}

type admissionRecord struct {
	Schema        string    `json:"schema"`
	ScopeDigest   string    `json:"scope_digest"`
	RequestDigest string    `json:"request_digest"`
	ContentDigest string    `json:"content_digest"`
	AdmittedAt    time.Time `json:"admitted_at"`
}

func NewAdmissionJournal(path string, scope NodeIdentity) (*AdmissionJournal, error) {
	if scope.Validate() != nil || scope.Identity != "spiffe://baseharbor/platform/connectors/"+scope.TenantID+"/"+scope.TargetID+"/"+scope.NodeID || path == "" || !filepath.IsAbs(path) {
		return nil, ErrAdmissionJournal
	}
	scope.InstanceID = ""
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, ErrAdmissionJournal
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrAdmissionJournal
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrAdmissionJournal
	}
	data, _ := json.Marshal(scope)
	digest := sha256.Sum256(data)
	journal := &AdmissionJournal{root: root, scope: scope, scopeDigest: hex.EncodeToString(digest[:]), maxRecords: maxAdmissionRecords}
	lock, err := journal.acquire(context.Background())
	if err != nil {
		root.Close()
		return nil, err
	}
	defer lock.Close()
	if err := journal.bindScope(data); err != nil {
		root.Close()
		return nil, err
	}
	return journal, nil
}

func (j *AdmissionJournal) Close() error {
	if j == nil || j.root == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.root.Close()
}

func (j *AdmissionJournal) acquire(ctx context.Context) (*os.File, error) {
	prior, statErr := j.root.Lstat("journal.lock")
	if statErr == nil && (!prior.Mode().IsRegular() || prior.Mode().Perm()&0077 != 0) {
		return nil, ErrAdmissionJournal
	}
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, ErrAdmissionJournal
	}
	file, err := j.root.OpenFile("journal.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrAdmissionJournal
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || (statErr == nil && !os.SameFile(prior, info)) {
		file.Close()
		return nil, ErrAdmissionJournal
	}
	if err := lockAdmissionFile(ctx, file); err != nil {
		file.Close()
		return nil, ErrAdmissionJournal
	}
	return file, nil
}

func (j *AdmissionJournal) bindScope(data []byte) error {
	file, err := j.root.OpenFile("scope.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		existing, err := j.readProtected("scope.json")
		if err != nil || !bytes.Equal(existing, data) {
			return ErrAdmissionJournal
		}
		return nil
	}
	if err != nil {
		return ErrAdmissionJournal
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return ErrAdmissionJournal
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return ErrAdmissionJournal
	}
	if err := file.Close(); err != nil {
		return ErrAdmissionJournal
	}
	return j.syncDirectory()
}

func (j *AdmissionJournal) syncDirectory() error {
	dir, err := j.root.Open(".")
	if err != nil {
		return ErrAdmissionJournal
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return ErrAdmissionJournal
	}
	return nil
}

func (j *AdmissionJournal) readProtected(name string) ([]byte, error) {
	info, err := j.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrAdmissionJournal
	}
	file, err := j.root.Open(name)
	if err != nil {
		return nil, ErrAdmissionJournal
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrAdmissionJournal
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAdmissionRecordBytes+1))
	if err != nil || len(data) > maxAdmissionRecordBytes {
		return nil, ErrAdmissionJournal
	}
	return data, nil
}

func (j *AdmissionJournal) Admit(ctx context.Context, request Request) error {
	if j == nil || request.Validate(time.Now().UTC()) != nil || request.TargetID != j.scope.TargetID {
		return ErrAdmissionJournal
	}
	err := j.admit(ctx, "request/"+request.RequestID, request)
	if err == nil && (request.Validate(time.Now().UTC()) != nil || ctx.Err() != nil) {
		return ErrAdmissionJournal
	}
	return err
}

func (j *AdmissionJournal) AdmitTerminal(ctx context.Context, open StreamOpen) error {
	if j == nil || open.Validate() != nil || open.Kind != StreamTerminal || open.TargetID != j.scope.TargetID || !open.DeadlineAt.After(time.Now()) || open.DeadlineAt.After(time.Now().Add(5*time.Minute)) {
		return ErrAdmissionJournal
	}
	err := j.admit(ctx, "terminal/"+open.StreamID, open)
	if err == nil && (!open.DeadlineAt.After(time.Now()) || ctx.Err() != nil) {
		return ErrAdmissionJournal
	}
	return err
}

func (j *AdmissionJournal) admit(ctx context.Context, id string, value any) error {
	select {
	case <-ctx.Done():
		return ErrAdmissionJournal
	default:
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return ErrAdmissionJournal
	}
	var canonical any
	if json.Unmarshal(raw, &canonical) != nil {
		return ErrAdmissionJournal
	}
	raw, err = json.Marshal(canonical)
	if err != nil {
		return ErrAdmissionJournal
	}
	content := sha256.Sum256(raw)
	key := sha256.Sum256([]byte(id))
	record := admissionRecord{Schema: "baseharbor.transport-admission/v1", ScopeDigest: j.scopeDigest, RequestDigest: hex.EncodeToString(key[:]), ContentDigest: hex.EncodeToString(content[:]), AdmittedAt: time.Now().UTC()}
	name := record.RequestDigest + ".admission"
	j.mu.Lock()
	defer j.mu.Unlock()
	lock, err := j.acquire(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	if existing, err := j.readProtected(name); err == nil {
		var prior admissionRecord
		decoder := json.NewDecoder(bytes.NewReader(existing))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&prior) != nil || decoder.Decode(new(any)) != io.EOF || prior.Schema != record.Schema || prior.ScopeDigest != record.ScopeDigest || prior.RequestDigest != record.RequestDigest || prior.AdmittedAt.IsZero() || len(prior.ContentDigest) != 64 {
			return ErrAdmissionJournal
		}
		if prior.ContentDigest != record.ContentDigest {
			return ErrReplayConflict
		}
		return ErrReplayAmbiguous
	} else if _, statErr := j.root.Lstat(name); !errors.Is(statErr, os.ErrNotExist) {
		return ErrAdmissionJournal
	}
	dir, err := j.root.Open(".")
	if err != nil {
		return ErrAdmissionJournal
	}
	entries, readErr := dir.ReadDir(j.maxRecords + 3)
	dir.Close()
	if readErr != nil && readErr != io.EOF {
		return ErrAdmissionJournal
	}
	if len(entries) >= j.maxRecords+2 {
		return ErrAdmissionJournal
	}
	select {
	case <-ctx.Done():
		return ErrAdmissionJournal
	default:
	}
	data, err := json.Marshal(record)
	if err != nil {
		return ErrAdmissionJournal
	}
	file, err := j.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrAdmissionJournal
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return ErrAdmissionJournal
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return ErrAdmissionJournal
	}
	if err := file.Close(); err != nil {
		return ErrAdmissionJournal
	}
	if err := j.syncDirectory(); err != nil {
		return ErrAdmissionJournal
	}
	if ctx.Err() != nil {
		return ErrAdmissionJournal
	}
	return nil
}

// RequiresAdmission treats exec and all realization/artifact primitives as
// side effects. Read-only observations may be repeated through new requests.
func RequiresAdmission(operation Operation) bool {
	switch operation {
	case OpRuntimeDetect, OpResourceList, OpResourceInspect, OpImageList, OpVolumeList, OpNetworkList, OpLogRead, OpMetrics, OpHealth, OpCapabilities:
		return false
	default:
		return true
	}
}
