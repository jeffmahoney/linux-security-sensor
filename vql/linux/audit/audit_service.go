package audit

import (
	"context"
	"errors"
	"fmt"
	"time"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.org/x/sync/errgroup"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/aucoalesce"
	"github.com/elastic/go-libaudit/v2/auparse"
	auditrule "github.com/elastic/go-libaudit/v2/rule"

	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	"www.velocidex.com/golang/velociraptor/file_store/api"
	"www.velocidex.com/golang/velociraptor/file_store/directory"
	"www.velocidex.com/golang/velociraptor/logging"
	"www.velocidex.com/golang/vfilter"
)

var (
	mu sync.Mutex
	gService *auditService

	// Timeout for batching audit configuration events
	gBatchTimeout = 1000 * time.Millisecond
	debugGoRoutines = false
	gDebugPrintingEnabled = true
	gMinimumSocketBufSize = 512 * 1024
	gMaxMessageTimeout = 5 * time.Second
	gMaxMessageQueueDepth = 2500
	gReassemblerMaintainerTimeout = 2 * time.Second
)

var gBannedRules = []string{
	"-d task,never",
}

type AtomicCounter struct {
	value int64
}

func (self *AtomicCounter) Add(val int) int {
	return int(atomic.AddInt64(&self.value, int64(val)))
}

func (self *AtomicCounter) Sub(val int) int {
	return int(atomic.AddInt64(&self.value, -int64(val)))
}

func (self *AtomicCounter) Inc() int {
	return self.Add(1)
}

func (self *AtomicCounter) Dec() int {
	return self.Sub(1)
}

func (self *AtomicCounter) Value() int {
	return int(atomic.LoadInt64(&self.value))
}

func (self *AtomicCounter) String() string {
	return fmt.Sprintf("%v", self.Value)
}

type RefcountedAuditRule struct {
	rule		AuditRule
	refcount	int
}

type commandClient interface {
	AddRule(rule []byte) error
	DeleteRule(rule []byte) error
	GetRules() ([][]byte, error)
	GetStatus() (*libaudit.AuditStatus, error)
	SetEnabled(enabled bool, wm libaudit.WaitMode) error
	Close() error
}

type auditService struct {
	config		*config_proto.Config
	serviceWg	sync.WaitGroup
	serviceLock	sync.Mutex
	logger		*logging.LogContext

	rulesLock	sync.Mutex
	rules		map[string]*RefcountedAuditRule
	bannedRules	map[string]*AuditRule

	// Once up and running, protected by rulesLock
	commandClient	commandClient
	reassembler	*libaudit.Reassembler

	logChannel	chan string
	checkerChannel	chan aucoalesce.Event
	running		bool
	shuttingDown	bool
	cancelService	func()

	messageQueue	*directory.ListenerBytes

	rawBufPool	sync.Pool
	msgPool		sync.Pool

	subscriberLock	sync.RWMutex
	subscribers	[]*subscriber

	// Used only for stats reporting
	totalMessagesReceivedCounter	AtomicCounter
	totalMessagesDiscardedCounter	AtomicCounter
	totalMessagesDroppedCounter	AtomicCounter
	totalMessagesPostedCounter	AtomicCounter
	totalRowsPostedCounter		AtomicCounter
	totalReceiveLoopCounter		AtomicCounter
	totalOutstandingMessageCounter	AtomicCounter
	currentMessagesQueuedCounter	AtomicCounter
}

func newAuditService(config_obj *config_proto.Config, logger *logging.LogContext) *auditService {
	bufSize := unix.NLMSG_HDRLEN + libaudit.AuditMessageMaxLength
	rawBufPool := sync.Pool {
		New: func() interface{} {
			return make([]byte, bufSize)
		},
	}
	msgPool := sync.Pool {
		New: func() interface{} {
			return &auparse.AuditMessage{}
		},
	}

	return &auditService{
		config:		config_obj,
		rules:		map[string]*RefcountedAuditRule{},
		bannedRules:	map[string]*AuditRule{},
		rawBufPool:	rawBufPool,
		msgPool:	msgPool,
		subscribers:	[]*subscriber{},
		logger:		logger,
	}
}

func (self *auditService) Debug(format string, v ...interface{}) {
	if gDebugPrintingEnabled {
		self.logger.Debug(format, v...)
	}
}

func (self *auditService) runService() error {
	var err error

	defer self.serviceLock.Unlock()
	self.serviceLock.Lock()

	// It's possible for another subscriber to attempt to start the
	// service and then fail, which will shut it down again.  We only
	// exit the loop in a known state: service is running or we need to
	// start it.
	for {
		if self.running {
			if !self.shuttingDown {
				return nil
			}

			// Wait for previous instance to shut down
			self.serviceLock.Unlock()
			self.serviceWg.Wait()
			self.serviceLock.Lock()
			continue
		}
		// Start the service
		break
	}

	self.logChannel = make(chan string, 2)
	self.checkerChannel = make(chan aucoalesce.Event)

	self.commandClient, err = libaudit.NewAuditClient(nil)
	if err != nil {
		return err
	}

	for _, rule := range gBannedRules {
		watcherRule, err := parseRule(rule)
		if err != nil {
			return fmt.Errorf("failed to parse built-in banned rule `%s': %w",
					  rule, err)
		}

		self.bannedRules[watcherRule.rule] = watcherRule
	}

	status, err := self.commandClient.GetStatus()
	if err != nil {
		self.commandClient.Close()
		return err
	}

	if status.Enabled == 0 {
		err = self.commandClient.SetEnabled(true, libaudit.WaitForReply)
		if err != nil {
			self.commandClient.Close()
			return fmt.Errorf("failed to enable audit subsystem: %w", err)
		}
		self.logger.Info("audit: enabled kernel audit subsystem")
	}

	self.reassembler, err = libaudit.NewReassembler(5, 500*time.Millisecond, self)
	if err != nil {
		self.commandClient.Close()
		return err
	}

	self.logger.Info("audit: starting audit service")
	self.running = true

	// This is a workaround for errgroup not returning a cancel func or
	// exporting the one it keeps for itself.  The choice is to either
	// reimplement errgroup with an exported cancel func or just
	// use the hierarchical nature of context cancelation to get the
	// same result.  The only difference is that we need to wait for
	// either context to signal Done.
	ctx, cancel := context.WithCancel(context.Background())
	grp, grpctx := errgroup.WithContext(ctx)

	options := api.QueueOptions{
		DisableFileBuffering: false,
		FileBufferLeaseSize: 4096,
		OwnerName: "audit-plugin",
	}

	self.messageQueue, err = directory.NewListenerBytes(self.config, grpctx, options.OwnerName,
						            options)
	if err != nil {
		cancel()
		self.commandClient.Close()
		self.running = false
		return err
	}

	// Start up the workers
	grp.Go(func() error { return self.logEventLoop(grpctx) })
	grp.Go(func() error { return self.startMaintainer(grpctx) })
	grp.Go(func() error { return self.startRulesChecker(grpctx) })
	grp.Go(func() error { return self.mainEventLoop(grpctx) })
	grp.Go(func() error { return self.listenerEventLoop(grpctx) })
	grp.Go(func() error { return self.reportStats(grpctx) })

	// Wait until we cancel the context or something hits an error
	go func() {
		self.Debug("audit: shutdown watcher starting")
		defer self.Debug("audit: shutdown watcher exited")

		select {
			// If we exit the main event loop normally
			case <-ctx.Done():
				break
			// If any of the goroutines exits abnormally
			case <-grpctx.Done():
				break
		}

		err := grp.Wait()
		if !errors.Is(err, context.Canceled) {
			self.logger.Info("audit: shutting down due to error ; err=%s", err)
		}

		self.shutdown()
	}()

	self.cancelService = cancel
	return nil
}

func (self *auditService) shutdown() {
	// If we're shutting down due to error, we'll still have subscribed callers
	self.subscriberLock.Lock()
	for _, subscriber := range self.subscribers {
		self.unsubscribe(subscriber, true)
	}
	self.subscribers = []*subscriber{}
	self.subscriberLock.Unlock()

	self.reassembler.Close()
	self.reassembler = nil

	self.commandClient.Close()
	self.commandClient = nil

	self.messageQueue.Close()
	self.messageQueue = nil

	close(self.logChannel)
	close(self.checkerChannel)

	self.bannedRules = map[string]*AuditRule{}
	self.rules = map[string]*RefcountedAuditRule{}

	self.logger.Info("audit: Shut down audit service")

	self.serviceLock.Lock()
	defer self.serviceLock.Unlock()

	self.running = false
	self.shuttingDown = false
	self.serviceWg.Done()
}

func openAuditListenerSocket() (int, error) {
	sockFd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return -1, err
	}

	src := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK,
					Groups: unix.AUDIT_NLGRP_READLOG}

	err = syscall.Bind(sockFd, src)
	if err != nil {
		syscall.Close(sockFd)
		return -1, fmt.Errorf("Could not bind to netlink socket: %w", err)
	}

	return sockFd, nil
}

func openEpollDescriptor(fd int) (int, error) {
	pollFd, err := unix.EpollCreate1(0)
	if err != nil {
		return -1, err
	}

	err = unix.EpollCtl(pollFd, unix.EPOLL_CTL_ADD, fd,
			    &unix.EpollEvent{Events: unix.POLLIN | unix.POLLHUP,
			    Fd: int32(fd)})
	if err != nil {
		syscall.Close(pollFd)
		return -1, err
	}

	return pollFd, nil
}

type RawAuditMessageBuf struct {
	Message		libaudit.RawAuditMessage
	Data		[]byte
}

func (self *auditService) acceptEvents(ctx context.Context, sockFd int) error {
	receivedCount := 0
	discardedCount := 0
	queuedCount := 0

	// We're in non-blocking mode.  Try to get all of the events we can in one go.
	var err error
	for {
		err = ctx.Err()
		if err != nil {
			break
		}

		buf := self.rawBufPool.Get().([]byte)
		msgType, size, err := self.receiveMessageBuf(sockFd, buf)
		if err != nil {
			self.rawBufPool.Put(buf)
			break
		}

		receivedCount += 1

		// Messages from 1300-2999 are valid audit messages.
		if msgType < auparse.AUDIT_USER_AUTH || msgType > auparse.AUDIT_LAST_USER_MSG2 {
			self.rawBufPool.Put(buf)
			discardedCount += 1
			continue
		}

		self.messageQueue.Send(buf[:size])
		queuedCount += 1
	}

	self.currentMessagesQueuedCounter.Add(queuedCount)
	self.totalMessagesReceivedCounter.Add(receivedCount)
	self.totalMessagesDiscardedCounter.Add(discardedCount)

	if errors.Is(err, unix.EAGAIN) ||
	   errors.Is(err, unix.EWOULDBLOCK) {
		err = nil
	}

	return err
}

func (self *auditService) processOneMessage(buf []byte) error {
	header := *(*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	msgType := auparse.AuditMessageType(header.Type)
	data := buf[unix.NLMSG_HDRLEN:]

	msgBuf := self.msgPool.Get().(*auparse.AuditMessage)
	err := auparse.ParseBytes(msgType, data, msgBuf)
	if err != nil {
		self.msgPool.Put(msgBuf)
		return err
	}

	self.reassembler.PushMessage(msgBuf)

	// These record types aren't included in the complete callback
	// but they still need to be pushed
	if msgBuf.RecordType == auparse.AUDIT_EOE {
		self.msgPool.Put(msgBuf)
		return nil
	}
	self.totalOutstandingMessageCounter.Inc()
	return nil
}

func (self *auditService) addSubscriberRules(subscriber *subscriber) error {
	added := []*AuditRule{}

	for _, rule := range subscriber.rules {
		err := self.addRule(rule)
		if err != nil {
			// This will at minimum roll back the refcounts
			for _, addedRule := range added {
				self.deleteRule(addedRule)
			}
			return err
		}
		added = append(added, rule)
	}

	return nil
}

func (self *auditService) removeSubscriberRules(subscriber *subscriber) error {
	for _, rule := range subscriber.rules {
		err := self.deleteRule(rule)
		if err != nil {
			msg := fmt.Sprintf("audit: failed to remove rule `%s' during unsubscribe: %s", rule.rule, err)
			subscriber.logChannel <- msg
			continue
		}
	}

	return nil
}

func (self *auditService) mainEventLoop(ctx context.Context) error {
	self.Debug("audit: mainEventLoop started")
	defer self.Debug("audit: mainEventLoop exited")
	wg := sync.WaitGroup{}
	defer wg.Wait()

	for {
		select {
		case <- ctx.Done():
			return ctx.Err()

		case buf, ok := <- self.messageQueue.Output():
			if !ok {
				return nil
			}
			err := self.processOneMessage(buf)
			if err != nil {
				self.logger.Info("failed to parse message: %v", err)
			}
			self.rawBufPool.Put(buf)
			self.currentMessagesQueuedCounter.Dec()
		}
	}
}

func (self *auditService) logEventLoop(ctx context.Context) error {
	self.Debug("audit: log event loop started")
	defer self.Debug("audit: log event loop exited")
	for {
		select {
		case msg, ok := <- self.logChannel:
			if !ok {
				break
			}

			self.subscriberLock.Lock()
			for _, subscriber := range self.subscribers {
				subscriber.logChannel <- msg
			}
			self.subscriberLock.Unlock()
			self.logger.Info(msg)
		}
	}

	return nil
}

func (self *auditService) listenerEventLoop(ctx context.Context) error {
	self.Debug("audit: listener event loop started")
	defer self.Debug("audit: listener event loop exited")

	sockFd, err := openAuditListenerSocket()
	if err != nil {
		return fmt.Errorf("could not open listener socket: %w", err)
	}
	defer syscall.Close(sockFd)

	epollFd, err := openEpollDescriptor(sockFd)
	if err != nil {
		return fmt.Errorf("could not open epoll socket: %w", err)
	}
	defer syscall.Close(epollFd)

	sockBufSize, err := unix.GetsockoptInt(sockFd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		return fmt.Errorf("could not get socket receive buffer size: %w", err)
	}

	if sockBufSize < gMinimumSocketBufSize {
		sockBufSize = gMinimumSocketBufSize
		err = unix.SetsockoptInt(sockFd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, sockBufSize)
		if err != nil {
			return fmt.Errorf("could not initialize socket receive buffer size (size %v): %w",
					  gMinimumSocketBufSize, err)
		}
	}

	poll_chan := make(chan int)
	error_chan := make(chan error)

	wg := sync.WaitGroup{}
	wg.Add(1)
	defer wg.Wait()
	go func(ctx context.Context) {
		defer wg.Done()
		defer close(error_chan)
		defer close(poll_chan)

		ready := make([]unix.EpollEvent, 2)
		for {
			select {
			case <- ctx.Done():
				return
			default:
				count, err := unix.EpollWait(epollFd, ready, 5000)
				if err != nil {
					if errors.Is(err, unix.EINTR) {
						continue
					}
					error_chan <- err
					return
				}
				poll_chan <- count
			}
		}
	}(ctx)

	for {
		select {
		case <- ctx.Done():
			return ctx.Err()
		case count, ok := <- poll_chan:
			if !ok  {
				continue
			}
			if count == 0 {
				// Timeout
				continue
			}
		case err, ok := <- error_chan:
			if !ok {
				continue
			}
			self.logger.Warn("audit: listenerEventLoop exiting after EpollWait returned %v",
					 err)
			return err
		}

		self.totalReceiveLoopCounter.Inc()
		err = self.acceptEvents(ctx, sockFd)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				return err
			}

			// Increase the size of the socket buffer and try again
			if errors.Is(err, unix.ENOBUFS) {
				sockBufSize *= 4
				err = unix.SetsockoptInt(sockFd, unix.SOL_SOCKET,
							 unix.SO_RCVBUFFORCE, sockBufSize)
				if err != nil {
					msg := fmt.Sprintf("audit: failed to increase listener socket buffer size: %v.  Events may be lost.", err)

					self.logChannel <- msg
				}
				continue
			}

			// The socket has been closed.
			if errors.Is(err, unix.EBADF) {
				// There likely won't be any listeners left and the socket
				// was closed in shutdown
				self.logChannel <- "audit: listener socket closed"
				return fmt.Errorf("listener socket closed: %w", err)
			}

			self.logChannel <- fmt.Sprintf("audit: receive failed: %s", err)
			return err
		}
	}
}

func (self *auditService) reportStats(ctx context.Context) error {
	lastReceived := 0
	lastDiscarded := 0
	lastDropped := 0
	lastQueued := 0
	lastPosted := 0
	lastMessagesPosted := 0

	if !gDebugPrintingEnabled {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <- time.After(5 * time.Second):
			break
		}

		received := self.totalMessagesReceivedCounter.Value()
		discarded := self.totalMessagesDiscardedCounter.Value()
		dropped := self.totalMessagesDroppedCounter.Value()
		posted := self.totalRowsPostedCounter.Value()
		messagesPosted := self.totalMessagesPostedCounter.Value()
		queued := self.currentMessagesQueuedCounter.Value()
		loops := self.totalReceiveLoopCounter.Value()
		outstandingMsgs := self.totalOutstandingMessageCounter.Value()
		if loops == 0 {
			loops = 1
		}

		self.logger.Debug("audit: ******************************** Received %d messages (%d rows) from kernel (diff %d (%d rows)) (averaging %d messages per loop over %d loops)",
		                  received, received / 6, received - lastReceived,
		                  (received - lastReceived) / 6, received / loops, loops)
		self.logger.Debug("audit: ******************************** Discarded %d messages from kernel (diff %d)",
				  discarded, discarded - lastDiscarded)

		self.logger.Debug("audit: ******************************** %d messages dropped (diff %d)",
		                  dropped, dropped - lastDropped)
		self.logger.Debug("audit: ******************************** %d messages posted (diff %d) (delta %v)",
		                  messagesPosted, messagesPosted - lastMessagesPosted,
				  received - dropped - messagesPosted - queued - discarded)
		self.logger.Debug("audit: ******************************** %d rows posted (diff %d)",
		                  posted, posted - lastPosted)

		self.logger.Debug("audit: ******************************** %d messages still queued (%d rows) (diff %d (%d rows))",
		                  queued, queued/6, queued - lastQueued, (queued - lastQueued) / 6)

		self.logger.Debug("audit: ******************************** current message count: %d",
				  outstandingMsgs)

		lastReceived = received
		lastDiscarded = discarded
		lastDropped = dropped
		lastPosted = posted
		lastQueued = queued
		lastMessagesPosted = messagesPosted
	}

	return nil
}

func (self *auditService) startMaintainer(ctx context.Context) error {
	self.Debug("audit: reassembler maintainer started")
	defer self.Debug("audit: reassembler maintainer exited")

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-time.After(gReassemblerMaintainerTimeout):
			// Maintain will only return error when closed
			if self.reassembler.Maintain() != nil {
				return nil
			}
		}
	}
}

// This executes as a synchronous callback via Reassembler.PushMessage
func (self *auditService) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	event, err := aucoalesce.CoalesceMessages(msgs)

	self.totalOutstandingMessageCounter.Sub(len(msgs))

	// Free the buffer for reuse
	for _, msg := range msgs {
		self.msgPool.Put(msg)
	}

	if err != nil {
		self.logger.Info("audit: failed to coalesce message: %v", err)
		return
	}

	// If the configuration has changed, kick off a scan to make sure our rules
	// are still in place
	if event.Category == aucoalesce.EventTypeConfig {
		self.checkerChannel <- *event
	}

	self.totalRowsPostedCounter.Inc()
	self.subscriberLock.RLock()
	for _, subscriber := range self.subscribers {
		subscriber.eventChannel <- *event
	}
	self.subscriberLock.RUnlock()
}

func (self *auditService) EventsLost(count int) {
	if count > 0x80000000 {
		count = 0x100000000 - count
	}
	self.logChannel <- fmt.Sprintf("Detected the loss of %v sequences.", count)
	self.totalMessagesDroppedCounter.Add(count)
}

func (self *auditService) addRuleToSubsystem(rule *auditrule.WireFormat) error {
	err := self.commandClient.AddRule(*rule)
	if err != nil && !strings.Contains(err.Error(), "rule exists") {
		return err
	}

	return nil
}

func (self *auditService) addRule(rule *AuditRule) error {
	self.rulesLock.Lock()
	defer self.rulesLock.Unlock()

	_, ok := self.rules[rule.rule]
	if ok {
		self.rules[rule.rule].refcount += 1
		return nil
	}

	err := self.addRuleToSubsystem(&rule.wfRule)
	if err != nil {
		return err
	}

	self.rules[rule.rule] = &RefcountedAuditRule{ rule: *rule, refcount: 1 }
	return nil
}

// Remove a reference to an audit rule.  If it's the last reference, remove it from
// the audit subsystem.
func (self *auditService) deleteRule(rule *AuditRule) error {
	self.rulesLock.Lock()
	defer self.rulesLock.Unlock()

	_, ok := self.rules[rule.rule]
	if ok {
		self.rules[rule.rule].refcount -= 1
		if self.rules[rule.rule].refcount == 0 {
			delete(self.rules, rule.rule)

			if self.commandClient == nil {
				return fmt.Errorf("audit: ERROR: Race detected between service shutdown and watcher shutdown.  Check locking, even implicit via logging.")
			}

			// If this fails, the rule will be left around
			// There's not a lot we can do about it except perhaps retry later
			// as a TODO
			err := self.commandClient.DeleteRule(rule.wfRule)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (self *auditService) notifyMissingRule(rule *AuditRule) {
	self.subscriberLock.Lock()
	defer self.subscriberLock.Lock()
	count := 0

	msg := fmt.Sprintf("audit: replaced missing rule `%v'", rule.rule)
	for _, subscriber := range self.subscribers {
		_, ok := subscriber.rules[rule.rule]
		if ok {
			subscriber.logChannel <- msg
			count += 1
		}
	}

	if count > 0 {
		self.logger.Info("audit: replaced missing rule `%v'", rule.rule)
	}
}

func (self *auditService) checkRules() error {
	self.rulesLock.Lock()
	defer self.rulesLock.Unlock()

	missing := 0

	rules, err := self.commandClient.GetRules()
	if err != nil {
		return err
	}

	activeRules := map[string]bool{}

	for _, rule := range rules {
		normalizedRule, err := auditrule.ToCommandLine([]byte(rule), true)
		if err != nil {
			return fmt.Errorf("Failed to normalize rule `%v': %v", rule, err)
		}

		activeRules[normalizedRule] = true
	}

	for text, rule := range self.rules {
		_, ok := activeRules[text]
		if ok {
			continue
		}

		self.notifyMissingRule(&rule.rule)
		err := self.addRuleToSubsystem(&rule.rule.wfRule)
		if err != nil {
			return err
		}
		missing += 1
	}

	if missing > 0 {
		self.Debug("audit: replaced %d missing rules", missing)
	}

	for text, rule := range self.bannedRules {
		_, ok := activeRules[text]
		if !ok {
			continue
		}

		if self.commandClient == nil {
			return fmt.Errorf("audit: ERROR: Race detected between service shutdown and rulesChecker.  Check locking, even implicit via logging.")
		}

		err := self.commandClient.DeleteRule(rule.wfRule)
		if err != nil {
			return err
		}
		self.logChannel <- fmt.Sprintf("audit: removed banned rule %v", text)
	}

	return nil
}

// This will allow us to treat a series of rule changes as a single event.  Otherwise, we'll
// end up checking the rules for _every_ event, which is just wasteful.
func (self *auditService) startRulesChecker(ctx context.Context) error {
	self.Debug("audit: rules checker started")
	defer self.Debug("audit: rules checker exited")

	for {
		select {
		case <- ctx.Done():
			return nil

		case <- time.After(gBatchTimeout):
			err := self.checkRules()
			if err != nil {
				self.logger.Warn("audit: rules check failed %v", err)
			}
		case <- self.checkerChannel:
			// Reset timer
			break
		}
	}
}

func (self *auditService) receiveMessageBuf(fd int, buf []byte) (msgType auparse.AuditMessageType, size int, err error) {
	if len(buf) < unix.NLMSG_HDRLEN {
		err = unix.EINVAL
		return
	}

	size, from, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
	if err != nil {
		// EAGAIN or EWOULDBLOCK will be returned for non-blocking reads where
		// the read would normally have blocked.
		return
	}
	if size < unix.NLMSG_HDRLEN {
		err = fmt.Errorf("not enough bytes (%v) received to form a netlink header", size)
		return
	}
	fromNetlink, ok := from.(*unix.SockaddrNetlink)
	if !ok || fromNetlink.Pid != 0 {
		// Spoofed packet received on audit netlink socket.
		err = errors.New("message received was not from the kernel")
		return
	}

	header := *(*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
	msgType = auparse.AuditMessageType(header.Type)
	return msgType, size, nil
}

func (self *auditService) unsubscribe(subscriber *subscriber, shuttingDown bool) {

	// If we're shutting down, we'll just clear the slice when we're done
	if !shuttingDown {
		for i, sub := range self.subscribers {
			if sub != subscriber {
				continue
			}
			newlen := len(self.subscribers) - 1
			self.subscribers[i] = self.subscribers[newlen]
			self.subscribers = self.subscribers[:newlen]
			break
		}
	}

	self.Debug("audit: removing subscriber, total now %v", len(self.subscribers))

	_ = self.removeSubscriberRules(subscriber)

	close(subscriber.eventChannel)
	close(subscriber.logChannel)

	if !shuttingDown {
		self.serviceLock.Lock()
		// No more subscribers: Shut it down
		if len(self.subscribers) == 0 {
			self.shuttingDown = true
			self.cancelService()
		}
		self.serviceLock.Unlock()
	}
}

func (self *auditService) Subscribe(rules []string) (AuditEventSubscriber, error) {
	subscriber := &subscriber{
			eventChannel: make(chan vfilter.Row, 2),
			logChannel:   make(chan string, 2),
			rules:	      map[string]*AuditRule{},
			wait:	      sync.WaitGroup{},}

	err := subscriber.addRules(rules)
	if err != nil {
		return nil, err
	}

	err = self.runService()
	if err != nil {
		return nil, err
	}

	defer self.subscriberLock.Unlock()
	self.subscriberLock.Lock()

	self.subscribers = append(self.subscribers, subscriber)
	self.Debug("audit: adding subscriber, total now %v", len(self.subscribers))
	err = self.addSubscriberRules(subscriber)
	if err != nil {
		self.unsubscribe(subscriber, false)
		return nil, err
	}

	return subscriber, nil
}

func (self *auditService) Unsubscribe(auditSubscriber AuditEventSubscriber) {
	defer self.subscriberLock.Unlock()
	self.subscriberLock.Lock()

	subscriber := auditSubscriber.(*subscriber)
	self.unsubscribe(subscriber, false)
}

type AuditEventSubscriber interface {
	Events() chan vfilter.Row
	LogEvents() chan string
}

type AuditService interface {
	Subscribe(rules []string) (AuditEventSubscriber, error)
	Unsubscribe(AuditEventSubscriber)
}

func GetAuditService(config_obj *config_proto.Config) AuditService {
	logger := logging.GetLogger(config_obj, &logging.ClientComponent)
	mu.Lock()
	defer mu.Unlock()

	if gService == nil {
		gService = newAuditService(config_obj, logger)
	}

	return AuditService(gService)
}
