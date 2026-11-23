package queue

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

// BenchmarkPushAndRun is one job through the queue: admission, the fair lane, a worker taking it and
// running it. The job itself does nothing, so the figure is the queue's own cost per push item.
func BenchmarkPushAndRun(b *testing.B) {
	q := New(256, 1<<20, 1<<20, time.Hour)
	defer q.Close(time.Second)
	instances := make([]string, 64)
	for i := range instances {
		instances[i] = "instance-" + strconv.Itoa(i)
	}
	var wg sync.WaitGroup
	n := 0
	for b.Loop() {
		wg.Add(1)
		if err := q.Push(&Job{Instance: instances[n%len(instances)], High: n%4 != 0, Run: wg.Done, Drop: wg.Done}); err != nil {
			b.Fatal(err)
		}
		n++
	}
	wg.Wait()
}
