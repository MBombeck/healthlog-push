package queue

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// TestFairAndPrioritised: with one worker blocked, queued jobs run high priority first and round robin
// across instances, so one busy instance cannot starve another.
func TestFairAndPrioritised(t *testing.T) {
	q := New(1, 100, 100, time.Hour)
	defer q.Close(time.Second)
	gate := make(chan struct{})
	var mu sync.Mutex
	var order []string
	done := make(chan struct{}, 100)
	add := func(inst string, high bool, name string) {
		if err := q.Push(&Job{Instance: inst, High: high, Run: func() {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			done <- struct{}{}
		}, Drop: func() {}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Push(&Job{Instance: "x", Run: func() { <-gate }, Drop: func() {}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	for k := range 3 {
		add("a", false, "a-low")
		add("a", true, "a"+string(rune('0'+k)))
	}
	add("b", true, "b0")
	add("b", false, "b-low")
	close(gate)
	for range 8 {
		<-done
	}
	want := []string{"a0", "b0", "a1", "a2", "a-low", "b-low", "a-low", "a-low"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order %v, want %v", order, want)
		}
	}
}

func TestAdmissionControl(t *testing.T) {
	q := New(1, 3, 2, time.Hour)
	block := make(chan struct{})
	defer func() { close(block); q.Close(time.Second) }()
	job := func(inst string) *Job { return &Job{Instance: inst, Run: func() { <-block }, Drop: func() {}} }
	_ = q.Push(job("z")) // occupies the worker
	time.Sleep(20 * time.Millisecond)
	if err := q.Push(job("a")); err != nil {
		t.Fatal(err)
	}
	_ = q.Push(job("a"))
	if err := q.Push(job("a")); !errors.Is(err, ErrInstanceFull) {
		t.Fatalf("per-instance cap: %v", err)
	}
	_ = q.Push(job("b"))
	if err := q.Push(job("c")); !errors.Is(err, ErrFull) {
		t.Fatalf("capacity: %v", err)
	}
}

func TestEstimatedWaitRefuses(t *testing.T) {
	q := New(1, 1000, 1000, 50*time.Millisecond)
	block := make(chan struct{})
	defer func() { close(block); q.Close(time.Second) }()
	q.mu.Lock()
	q.avgService = 40 * time.Millisecond
	q.mu.Unlock()
	_ = q.Push(&Job{Instance: "z", Run: func() { <-block }, Drop: func() {}})
	time.Sleep(10 * time.Millisecond)
	var err error
	for range 5 {
		if err = q.Push(&Job{Instance: "a", Run: func() {}, Drop: func() {}}); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrFull) {
		t.Fatalf("admission by estimated wait: %v", err)
	}
}

func TestStaleJobsDropped(t *testing.T) {
	q := New(1, 10, 10, 30*time.Millisecond)
	defer q.Close(time.Second)
	q.mu.Lock()
	q.avgService = time.Millisecond
	q.mu.Unlock()
	block := make(chan struct{})
	_ = q.Push(&Job{Instance: "z", Run: func() { <-block }, Drop: func() {}})
	time.Sleep(10 * time.Millisecond)
	dropped := make(chan struct{})
	if err := q.Push(&Job{Instance: "a", Run: func() { t.Error("stale job ran") }, Drop: func() { close(dropped) }}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	close(block)
	select {
	case <-dropped:
	case <-time.After(time.Second):
		t.Fatal("stale job neither ran nor dropped")
	}
}

// TestRecoversAfterSlowSends: after a run of sends that each hit the timeout, an empty queue still accepts
// work, and the average falls again once sends are fast.
func TestRecoversAfterSlowSends(t *testing.T) {
	q := New(1, 100, 100, 50*time.Millisecond)
	defer q.Close(time.Second)
	for range 8 {
		done := make(chan struct{})
		if err := q.Push(&Job{Instance: "a", Run: func() { time.Sleep(80 * time.Millisecond); close(done) }, Drop: func() {}}); err != nil {
			t.Fatalf("slow job refused: %v", err)
		}
		<-done
	}
	time.Sleep(10 * time.Millisecond)
	done := make(chan struct{})
	if err := q.Push(&Job{Instance: "a", Run: func() { close(done) }, Drop: func() {}}); err != nil {
		t.Fatalf("empty queue refuses after slow sends: %v", err)
	}
	<-done
}
