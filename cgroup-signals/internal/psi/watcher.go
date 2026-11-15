package psi

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// pollTimeoutMS bounds how long Run waits in epoll_wait before it looks at
// its context again.
const pollTimeoutMS = 500

// Handler receives a Watcher's events. It is called from Run's goroutine,
// without any of the Watcher's locks held, so it may call Remove.
type Handler interface {
	// Event is called once per trigger event on key's res file.
	Event(key string, res Resource)
	// Gone is called when a file of key reports EPOLLERR or EPOLLHUP: the
	// cgroup was removed (kernfs then fails every poll with EPOLLERR).
	Gone(key string)
}

type watch struct {
	key string
	res Resource
	fd  int
}

// Watcher waits for POLLPRI on PSI trigger file descriptors, all of them in
// one epoll set and from one goroutine (Run).
type Watcher struct {
	epfd    int
	trigger Trigger
	handler Handler

	mu sync.Mutex
	// next is the id of the next watch. The epoll event carries the id
	// rather than the fd, so an event harvested for a descriptor that was
	// just closed (and maybe reused) is not taken for its successor's.
	next  int32
	byID  map[int32]*watch
	byKey map[string][]int32
}

// NewWatcher returns a Watcher that arms t and reports to h.
func NewWatcher(t Trigger, h Handler) (*Watcher, error) {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("epoll_create1: %w", err)
	}
	return &Watcher{
		epfd:    epfd,
		trigger: t,
		handler: h,
		byID:    make(map[int32]*watch),
		byKey:   make(map[string][]int32),
	}, nil
}

// Watch arms the Watcher's trigger on path, res's pressure file of the
// cgroup key, and adds it to the epoll set.
func (w *Watcher) Watch(key string, res Resource, path string) error {
	fd, err := Arm(path, w.trigger)
	if err != nil {
		return err
	}
	return w.Add(key, res, fd)
}

// Add adds fd, already armed, to the epoll set under key. The Watcher owns fd
// from then on, and closes it on Remove or Close, or here on failure.
func (w *Watcher) Add(key string, res Resource, fd int) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.next++
	id := w.next
	// Edge-triggered: one report per wakeup. PSI wakes the file's waiters
	// once per event, and the poll that epoll then makes consumes the event.
	ev := unix.EpollEvent{Events: unix.EPOLLPRI | unix.EPOLLET, Fd: id}
	if err := unix.EpollCtl(w.epfd, unix.EPOLL_CTL_ADD, fd, &ev); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("epoll_ctl add: %w", err)
	}
	w.byID[id] = &watch{key: key, res: res, fd: fd}
	w.byKey[key] = append(w.byKey[key], id)
	return nil
}

// Remove closes every file descriptor held for key; closing a descriptor
// destroys its trigger.
func (w *Watcher) Remove(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, id := range w.byKey[key] {
		w.closeLocked(id)
	}
	delete(w.byKey, key)
}

func (w *Watcher) closeLocked(id int32) {
	wt := w.byID[id]
	delete(w.byID, id)
	// Closing the descriptor also takes it out of the epoll set; the
	// explicit delete only makes that independent of dup'd descriptors.
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, wt.fd, nil)
	_ = unix.Close(wt.fd)
}

// Len is the number of open trigger file descriptors.
func (w *Watcher) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.byID)
}

// Run waits for events until ctx is done.
func (w *Watcher) Run(ctx context.Context) error {
	events := make([]unix.EpollEvent, 64)
	for ctx.Err() == nil {
		n, err := unix.EpollWait(w.epfd, events, pollTimeoutMS)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("epoll_wait: %w", err)
		}
		for _, ev := range events[:n] {
			w.dispatch(ev)
		}
	}
	return nil
}

func (w *Watcher) dispatch(ev unix.EpollEvent) {
	w.mu.Lock()
	wt, ok := w.byID[ev.Fd]
	w.mu.Unlock()
	if !ok {
		return // removed since epoll_wait harvested it
	}
	// A removed cgroup's file polls as EPOLLERR|EPOLLPRI, so the error is
	// checked first: it is not a stall.
	if ev.Events&(unix.EPOLLERR|unix.EPOLLHUP) != 0 {
		w.handler.Gone(wt.key)
		return
	}
	if ev.Events&unix.EPOLLPRI != 0 {
		w.handler.Event(wt.key, wt.res)
	}
}

// Close closes every trigger descriptor and the epoll set. Call it after Run
// has returned.
func (w *Watcher) Close() error {
	w.mu.Lock()
	for id := range w.byID {
		w.closeLocked(id)
	}
	clear(w.byKey)
	w.mu.Unlock()
	return unix.Close(w.epfd)
}
