// Package queue is the in-memory send queue: a bounded ring per instance, served round robin across
// instances, with high priority (alert, Live Activity) before low priority (silent). Admission control
// refuses work whose estimated wait exceeds MaxWait instead of letting the queue grow, and work that waited
// longer than MaxWait anyway is dropped at dequeue. Nothing is written to disk.
package queue

import (
	"errors"
	"sync"
	"time"
)

// Limits of the queue (spec/protocol.md, "Queue").
const (
	DefaultCapacity    = 4096
	DefaultPerInstance = 256
	DefaultMaxWait     = 2 * time.Second
)

// Errors returned by Push.
var (
	ErrFull         = errors.New("queue full")
	ErrInstanceFull = errors.New("instance queue full")
	ErrClosed       = errors.New("queue closed")
)

// Job is one unit of work. Run is called by a worker; Drop is called instead when the job waited too long
// or the queue closed.
type Job struct {
	Instance string
	High     bool
	Run      func()
	Drop     func()
	enq      time.Time
}

type ring struct {
	jobs []*Job
}

type lane struct {
	per   map[string]*ring
	order []string // round robin order of instances with work
	next  int
}

func newLane() *lane { return &lane{per: map[string]*ring{}} }

func (l *lane) push(j *Job) {
	r := l.per[j.Instance]
	if r == nil {
		r = &ring{}
		l.per[j.Instance] = r
		l.order = append(l.order, j.Instance)
	}
	r.jobs = append(r.jobs, j)
}

func (l *lane) pop() *Job {
	if len(l.order) == 0 {
		return nil
	}
	if l.next >= len(l.order) {
		l.next = 0
	}
	inst := l.order[l.next]
	r := l.per[inst]
	j := r.jobs[0]
	r.jobs[0] = nil
	r.jobs = r.jobs[1:]
	if len(r.jobs) == 0 {
		delete(l.per, inst)
		l.order = append(l.order[:l.next], l.order[l.next+1:]...)
	} else {
		l.next++
	}
	return j
}

// Queue is a fair, bounded queue served by a fixed number of workers.
type Queue struct {
	mu          sync.Mutex
	cond        *sync.Cond
	high, low   *lane
	total       int
	perInst     map[string]int
	capacity    int
	perInstance int
	maxWait     time.Duration
	workers     int
	avgService  time.Duration // moving average of job run time
	closed      bool
	wg          sync.WaitGroup
	now         func() time.Time
	OnDrop      func()
}

// New starts a queue with the given number of workers.
func New(workers, capacity, perInstance int, maxWait time.Duration) *Queue {
	q := &Queue{
		high: newLane(), low: newLane(), perInst: map[string]int{},
		capacity: capacity, perInstance: perInstance, maxWait: maxWait, workers: workers,
		avgService: 100 * time.Millisecond, now: time.Now,
	}
	q.cond = sync.NewCond(&q.mu)
	for range workers {
		q.wg.Add(1)
		go q.worker()
	}
	return q
}

// estimate is the expected wait for a new job of the given priority. Caller holds q.mu.
func (q *Queue) estimate(high bool) time.Duration {
	ahead := q.total
	if high {
		ahead = q.countLane(q.high)
	}
	return time.Duration(int64(ahead/q.workers+1)) * q.avgService
}

func (q *Queue) countLane(l *lane) int {
	n := 0
	for _, r := range l.per {
		n += len(r.jobs)
	}
	return n
}

// Push admits a job or refuses it at once.
func (q *Queue) Push(j *Job) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	switch {
	case q.closed:
		return ErrClosed
	case q.total >= q.capacity:
		return ErrFull
	case q.perInst[j.Instance] >= q.perInstance:
		return ErrInstanceFull
	case q.estimate(j.High) > q.maxWait:
		return ErrFull
	}
	j.enq = q.now()
	if j.High {
		q.high.push(j)
	} else {
		q.low.push(j)
	}
	q.total++
	q.perInst[j.Instance]++
	q.cond.Signal()
	return nil
}

// Len returns the number of queued jobs.
func (q *Queue) Len() int { q.mu.Lock(); defer q.mu.Unlock(); return q.total }

func (q *Queue) take() *Job {
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.total == 0 && !q.closed {
		q.cond.Wait()
	}
	if q.total == 0 {
		return nil
	}
	j := q.high.pop()
	if j == nil {
		j = q.low.pop()
	}
	q.total--
	q.perInst[j.Instance]--
	if q.perInst[j.Instance] <= 0 {
		delete(q.perInst, j.Instance)
	}
	return j
}

func (q *Queue) worker() {
	defer q.wg.Done()
	for {
		j := q.take()
		if j == nil {
			return
		}
		if q.now().Sub(j.enq) > q.maxWait {
			if q.OnDrop != nil {
				q.OnDrop()
			}
			j.Drop()
			continue
		}
		start := q.now()
		j.Run()
		d := q.now().Sub(start)
		q.mu.Lock()
		q.avgService = (q.avgService*7 + d) / 8
		q.mu.Unlock()
	}
}

// Close stops accepting jobs, drops queued ones and waits up to timeout for running jobs.
func (q *Queue) Close(timeout time.Duration) {
	q.mu.Lock()
	q.closed = true
	var pending []*Job
	for _, l := range []*lane{q.high, q.low} {
		for j := l.pop(); j != nil; j = l.pop() {
			pending = append(pending, j)
		}
	}
	q.total = 0
	q.perInst = map[string]int{}
	q.cond.Broadcast()
	q.mu.Unlock()
	for _, j := range pending {
		j.Drop()
	}
	done := make(chan struct{})
	go func() { q.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}
