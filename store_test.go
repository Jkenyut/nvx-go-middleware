package middleware

import (
	"context"
	"errors"
	"testing"

	"github.com/Jkenyut/nvx-go-middleware/model"
)

type recordingStore struct {
	entries []*model.AuditLog
	err     error
}

func (r *recordingStore) Save(_ context.Context, entry *model.AuditLog) error {
	if r.err != nil {
		return r.err
	}
	r.entries = append(r.entries, entry)
	return nil
}

func TestMultiLogStore_Broadcast(t *testing.T) {
	s1 := &recordingStore{}
	s2 := &recordingStore{}

	multi := MultiLogStore(nil, s1, nil, s2)
	entry := &model.AuditLog{ID: "test-id", Method: "GET"}

	if err := multi.Save(context.Background(), entry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(s1.entries) != 1 || s1.entries[0].ID != "test-id" {
		t.Errorf("s1 did not receive entry: %+v", s1.entries)
	}
	if len(s2.entries) != 1 || s2.entries[0].ID != "test-id" {
		t.Errorf("s2 did not receive entry: %+v", s2.entries)
	}
}

func TestMultiLogStore_ErrorAggregation(t *testing.T) {
	err1 := errors.New("store 1 failed")
	err2 := errors.New("store 2 failed")

	s1 := &recordingStore{err: err1}
	s2 := &recordingStore{err: err2}
	s3 := &recordingStore{}

	multi := MultiLogStore(s1, s2, s3)
	entry := &model.AuditLog{ID: "err-id"}

	err := multi.Save(context.Background(), entry)
	if err == nil {
		t.Fatal("expected aggregated error, got nil")
	}

	if !errors.Is(err, err1) || !errors.Is(err, err2) {
		t.Errorf("expected errors.Join containing err1 and err2, got: %v", err)
	}
	if len(s3.entries) != 1 {
		t.Errorf("s3 should still receive entry even if preceding stores fail")
	}
}

func TestConsoleStore_NilSafety(t *testing.T) {
	entry := &model.AuditLog{ID: "test-id"}

	// 1. Nil receiver
	var nilStore *ConsoleStore
	if err := nilStore.Save(context.Background(), entry); err != nil {
		t.Errorf("expected nil error on nil receiver, got %v", err)
	}

	// 2. Nil logger
	emptyStore := &ConsoleStore{}
	if err := emptyStore.Save(context.Background(), entry); err != nil {
		t.Errorf("expected nil error on empty store, got %v", err)
	}

	// 3. Nil entry
	if err := emptyStore.Save(context.Background(), nil); err != nil {
		t.Errorf("expected nil error on nil entry, got %v", err)
	}
}

func TestMultiLogStore_SingleStore(t *testing.T) {
	s1 := &recordingStore{}
	multi := MultiLogStore(nil, s1, nil)

	if multi != s1 {
		t.Errorf("expected single store to be returned directly, got %T", multi)
	}
}

func TestMultiLogStore_Flattening(t *testing.T) {
	s1 := &recordingStore{}
	s2 := &recordingStore{}
	s3 := &recordingStore{}

	nested := MultiLogStore(s2, s3)
	multi := MultiLogStore(s1, nested)

	entry := &model.AuditLog{ID: "flatten-id"}
	if err := multi.Save(context.Background(), entry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(s1.entries) != 1 || len(s2.entries) != 1 || len(s3.entries) != 1 {
		t.Errorf("expected all stores to receive entry, got s1=%d, s2=%d, s3=%d",
			len(s1.entries), len(s2.entries), len(s3.entries))
	}
}

func TestMultiLogStore_Empty(t *testing.T) {
	multi := MultiLogStore(nil, nil)
	entry := &model.AuditLog{ID: "empty-id"}

	if err := multi.Save(context.Background(), entry); err != nil {
		t.Errorf("expected nil error for empty MultiLogStore, got %v", err)
	}
}
