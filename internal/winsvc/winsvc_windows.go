//go:build windows

package winsvc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// Windows API entry points, resolved lazily at first use.
var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procStartServiceCtrlDispatcherW = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerW = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus            = advapi32.NewProc("SetServiceStatus")
	procOpenSCManagerW              = advapi32.NewProc("OpenSCManagerW")
	procCreateServiceW              = advapi32.NewProc("CreateServiceW")
	procOpenServiceW                = advapi32.NewProc("OpenServiceW")
	procDeleteService               = advapi32.NewProc("DeleteService")
	procCloseServiceHandle          = advapi32.NewProc("CloseServiceHandle")
	procStartServiceW               = advapi32.NewProc("StartServiceW")
	procControlService              = advapi32.NewProc("ControlService")
	procQueryServiceStatus          = advapi32.NewProc("QueryServiceStatus")
	procChangeServiceConfig2W       = advapi32.NewProc("ChangeServiceConfig2W")
)

// Win32 constants. Spelled out rather than imported so that every value the ABI
// depends on is visible in this file.
const (
	serviceWin32OwnProcess = 0x00000010
	serviceAutoStart       = 0x00000002
	serviceErrorNormal     = 0x00000001

	scManagerAllAccess = 0xF003F
	serviceAllAccess   = 0xF01FF

	// States, as the SCM reports and expects them.
	svcStopped      = 1
	svcStartPending = 2
	svcStopPending  = 3
	svcRunning      = 4

	// Controls a service declares it can handle. Declaring one it cannot handle
	// means the SCM waits for a response that never comes.
	acceptStop     = 0x00000001
	acceptShutdown = 0x00000004

	// Control codes the SCM sends.
	controlStop        = 0x00000001
	controlInterrogate = 0x00000004
	controlShutdown    = 0x00000005
	controlPreShutdown = 0x0000000F

	// ChangeServiceConfig2W info levels.
	configDescription      = 1
	configFailureActions   = 2
	configDelayedAutoStart = 3

	// Failure action types.
	scActionRestart = 1

	// Error codes worth distinguishing from each other.
	errFailedServiceControllerConnect = 1063
	errServiceDoesNotExist            = 1060
	errServiceExists                  = 1073
	errServiceMarkedForDelete         = 1072
	errAccessDenied                   = 5
	errServiceNotActive               = 1062
)

// serviceStatus mirrors the Win32 SERVICE_STATUS structure.
//
// Field order and widths must match exactly: this is passed by pointer across an
// ABI boundary, and a mismatch would be read as garbage rather than rejected.
type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

// serviceTableEntry mirrors SERVICE_TABLE_ENTRYW.
type serviceTableEntry struct {
	Name *uint16
	Proc uintptr
}

// serviceDescription mirrors SERVICE_DESCRIPTIONW.
type serviceDescription struct {
	Description *uint16
}

// serviceDelayedAutoStartInfo mirrors SERVICE_DELAYED_AUTO_START_INFO.
type serviceDelayedAutoStartInfo struct {
	DelayedAutostart uint32 // BOOL
}

// scAction mirrors SC_ACTION.
type scAction struct {
	Type  uint32
	Delay uint32 // milliseconds
}

// serviceFailureActions mirrors SERVICE_FAILURE_ACTIONSW.
type serviceFailureActions struct {
	ResetPeriod  uint32 // seconds
	RebootMsg    *uint16
	Command      *uint16
	ActionsCount uint32
	Actions      *scAction
}

func supported() bool { return true }

// serviceState is the state shared between the SCM callbacks and Run.
//
// It is package-level because the callbacks Windows invokes cannot carry a Go
// closure: syscall.NewCallback produces a plain C function pointer, so anything
// the callback needs has to be reachable without an argument.
var serviceState struct {
	mu sync.Mutex

	name      string
	fn        func(context.Context) error
	cancel    context.CancelFunc
	statusH   uintptr
	checkNext uint32

	done   chan struct{}
	runErr error
}

// Callbacks are kept in package-level variables so the garbage collector cannot
// move or free them. Windows holds these pointers for the life of the process.
var (
	serviceMainCallback = syscall.NewCallback(serviceMain)
	handlerCallback     = syscall.NewCallback(serviceHandler)
)

// isServiceResult caches the outcome of the dispatcher probe, because the probe
// can only be made once per process.
var isServiceResult atomic.Int32 // 0 unknown, 1 yes, 2 no

func isService() bool {
	switch isServiceResult.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	// Unknown until Run has tried the dispatcher. Callers that need to know
	// before then are asking a question this cannot answer cheaply.
	return false
}

// run connects to the service control dispatcher, falling back to running
// directly when this process was not started by the SCM.
//
// The fallback is decided by the specific error the dispatcher returns rather
// than by inspecting the environment: ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
// means "you are not a service", and any other failure is a real problem that
// should not be silently turned into a console run.
func run(name string, f func(context.Context) error) error {
	serviceState.mu.Lock()
	serviceState.name = name
	serviceState.fn = f
	serviceState.done = make(chan struct{})
	serviceState.mu.Unlock()

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("winsvc: service name: %w", err)
	}

	table := []serviceTableEntry{
		{Name: namePtr, Proc: serviceMainCallback},
		{}, // the table is terminated by a zero entry
	}

	r, _, callErr := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if r == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && uintptr(errno) == errFailedServiceControllerConnect {
			// Started from a console. Run in the foreground, which is also how
			// the service is debugged.
			isServiceResult.Store(2)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			return f(ctx)
		}
		return fmt.Errorf("winsvc: StartServiceCtrlDispatcher: %w", callErr)
	}

	// The dispatcher returns once the service has stopped.
	isServiceResult.Store(1)
	<-serviceState.done

	serviceState.mu.Lock()
	defer serviceState.mu.Unlock()
	return serviceState.runErr
}

// serviceMain is what the SCM calls to start the service.
//
// It must register a control handler and report a status quickly. A service that
// does not report within the SCM's window is killed, so the first status report
// happens before any real work begins.
func serviceMain(argc uint32, argv **uint16) uintptr {
	serviceState.mu.Lock()
	name := serviceState.name
	fn := serviceState.fn
	serviceState.mu.Unlock()

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0
	}

	h, _, _ := procRegisterServiceCtrlHandlerW.Call(
		uintptr(unsafe.Pointer(namePtr)),
		handlerCallback,
		0, // context, unused: the callback reaches state through package scope
	)
	if h == 0 {
		return 0
	}

	ctx, cancel := context.WithCancel(context.Background())

	serviceState.mu.Lock()
	serviceState.statusH = h
	serviceState.cancel = cancel
	serviceState.mu.Unlock()

	// Tell the SCM we are starting, then that we are running. The two-step is
	// not ceremony: a service that reports Running before it can serve will have
	// dependent services started against it too early.
	reportStatus(svcStartPending, 0, 10_000)
	reportStatus(svcRunning, acceptStop|acceptShutdown, 0)

	err = fn(ctx)

	serviceState.mu.Lock()
	// Cancellation is the normal way a service stops and is not an error.
	if err != nil && !errors.Is(err, context.Canceled) {
		serviceState.runErr = err
	}
	serviceState.mu.Unlock()

	// A non-zero exit code is what makes the SCM's restart policy fire. Reporting
	// zero after a crash would leave a dead agent looking like a clean shutdown.
	exitCode := uint32(0)
	if serviceState.runErr != nil {
		exitCode = 1
	}
	reportStatusExit(svcStopped, 0, 0, exitCode)

	cancel()
	close(serviceState.done)
	return 0
}

// serviceHandler receives control requests from the SCM.
//
// It must return quickly. Anything slow is done by cancelling the context and
// letting the service's own goroutine wind down, while this reports
// STOP_PENDING so the SCM keeps waiting instead of killing the process.
func serviceHandler(control uint32, eventType uint32, eventData uintptr, context uintptr) uintptr {
	switch control {
	case controlStop, controlShutdown, controlPreShutdown:
		reportStatus(svcStopPending, 0, 15_000)

		serviceState.mu.Lock()
		cancel := serviceState.cancel
		serviceState.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		return 0

	case controlInterrogate:
		// Answering means re-reporting the current status, which the SCM uses to
		// confirm the service is still responsive.
		serviceState.mu.Lock()
		h := serviceState.statusH
		serviceState.mu.Unlock()
		if h != 0 {
			reportStatus(svcRunning, acceptStop|acceptShutdown, 0)
		}
		return 0

	default:
		// ERROR_CALL_NOT_IMPLEMENTED. Declaring only the controls we accept and
		// refusing the rest is better than pretending to handle them.
		return 1
	}
}

func reportStatus(state, accepted, waitHintMS uint32) {
	reportStatusExit(state, accepted, waitHintMS, 0)
}

// reportStatusExit sends a status to the SCM.
//
// The check point must advance on every pending report. It is how the SCM tells
// a service that is slow to stop from one that has hung: a check point that
// stops moving means no progress, and the service is killed.
func reportStatusExit(state, accepted, waitHintMS, exitCode uint32) {
	serviceState.mu.Lock()
	h := serviceState.statusH
	if state == svcStartPending || state == svcStopPending {
		serviceState.checkNext++
	} else {
		serviceState.checkNext = 0
	}
	checkPoint := serviceState.checkNext
	serviceState.mu.Unlock()

	if h == 0 {
		return
	}

	st := serviceStatus{
		ServiceType:   serviceWin32OwnProcess,
		CurrentState:  state,
		Win32ExitCode: exitCode,
		CheckPoint:    checkPoint,
		WaitHint:      waitHintMS,
	}
	// Controls are only accepted while running. Advertising them in a pending
	// state invites the SCM to send a control the service cannot yet handle.
	if state == svcRunning {
		st.ControlsAccepted = accepted
	}

	procSetServiceStatus.Call(h, uintptr(unsafe.Pointer(&st)))
}
