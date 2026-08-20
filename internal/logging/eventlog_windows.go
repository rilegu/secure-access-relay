//go:build windows

package logging

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Windows Event Log, reached through the standard library for the same reason as
// DPAPI and the service control manager: no external dependency.
var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procRegisterEventSourceW  = advapi32.NewProc("RegisterEventSourceW")
	procDeregisterEventSource = advapi32.NewProc("DeregisterEventSource")
	procReportEventW          = advapi32.NewProc("ReportEventW")
	procRegCreateKeyExW       = advapi32.NewProc("RegCreateKeyExW")
	procRegSetValueExW        = advapi32.NewProc("RegSetValueExW")
	procRegCloseKey           = advapi32.NewProc("RegCloseKey")
	procRegDeleteKeyW         = advapi32.NewProc("RegDeleteKeyW")
)

const (
	hkeyLocalMachine = 0x80000002
	keyAllAccess     = 0xF003F

	regSZ       = 1
	regExpandSZ = 2
	regDWORD    = 4

	eventLogError       = 1
	eventLogWarning     = 2
	eventLogInformation = 4

	// eventTypesSupported is the bitmask of severities this source will emit.
	eventTypesSupported = eventLogError | eventLogWarning | eventLogInformation

	// genericEventID is the message identifier used for every event.
	//
	// A proper Windows service ships a message resource DLL mapping identifiers
	// to formatted text. This project has no such resource, so it points
	// EventMessageFile at a system binary whose message table contains generic
	// entries that simply print their insertion string. The event therefore reads
	// as the message that was logged, rather than as "the description for event
	// ID N cannot be found".
	//
	// The honest trade: no categories, no per-event formatting, no localisation.
	// For operational events that are already structured JSON elsewhere, that is
	// an acceptable amount to give up, and it avoids shipping a compiled resource
	// nobody would maintain.
	genericEventID = 1000

	// messageFile provides the generic message table described above.
	messageFile = `%SystemRoot%\System32\EventCreate.exe`
)

// eventSourceKey is where Windows looks for a source's configuration.
func eventSourceKey(source string) string {
	return `SYSTEM\CurrentControlSet\Services\EventLog\Application\` + source
}

// registerEventSource creates the registry entries Windows needs before events
// from this source display correctly.
//
// Needs Administrator rights, which is why it happens at install time rather
// than at startup: a service that tried to register its own source on every run
// would either need write access to HKLM permanently, or would log a permission
// error every time it started.
func registerEventSource(source string) error {
	keyPath, err := syscall.UTF16PtrFromString(eventSourceKey(source))
	if err != nil {
		return err
	}

	var handle uintptr
	var disposition uint32
	r, _, callErr := procRegCreateKeyExW.Call(
		hkeyLocalMachine,
		uintptr(unsafe.Pointer(keyPath)),
		0, // reserved
		0, // class
		0, // options
		keyAllAccess,
		0, // security attributes
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(&disposition)),
	)
	if r != 0 {
		return fmt.Errorf("logging: create event source key: %w", callErr)
	}
	defer procRegCloseKey.Call(handle)

	if err := setStringValue(handle, "EventMessageFile", messageFile, regExpandSZ); err != nil {
		return err
	}
	if err := setDWORDValue(handle, "TypesSupported", eventTypesSupported); err != nil {
		return err
	}
	return nil
}

// deregisterEventSource removes the registry entries, so an uninstall leaves
// nothing behind.
func deregisterEventSource(source string) error {
	keyPath, err := syscall.UTF16PtrFromString(eventSourceKey(source))
	if err != nil {
		return err
	}
	r, _, callErr := procRegDeleteKeyW.Call(hkeyLocalMachine, uintptr(unsafe.Pointer(keyPath)))
	if r != 0 {
		return fmt.Errorf("logging: delete event source key: %w", callErr)
	}
	return nil
}

func setStringValue(key uintptr, name, value string, valueType uintptr) error {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	data, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	// Size is in bytes and includes the terminating NUL, which UTF16FromString
	// already appended.
	size := uintptr(len(data) * 2)
	r, _, callErr := procRegSetValueExW.Call(
		key,
		uintptr(unsafe.Pointer(namePtr)),
		0,
		valueType,
		uintptr(unsafe.Pointer(&data[0])),
		size,
	)
	if r != 0 {
		return fmt.Errorf("logging: set %s: %w", name, callErr)
	}
	return nil
}

func setDWORDValue(key uintptr, name string, value uint32) error {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r, _, callErr := procRegSetValueExW.Call(
		key,
		uintptr(unsafe.Pointer(namePtr)),
		0,
		regDWORD,
		uintptr(unsafe.Pointer(&value)),
		unsafe.Sizeof(value),
	)
	if r != 0 {
		return fmt.Errorf("logging: set %s: %w", name, callErr)
	}
	return nil
}

// eventLogWriter holds an open handle to the Event Log.
type eventLogWriter struct {
	handle uintptr
}

func openEventLog(source string) (*eventLogWriter, error) {
	srcPtr, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return nil, err
	}
	h, _, callErr := procRegisterEventSourceW.Call(0, uintptr(unsafe.Pointer(srcPtr)))
	if h == 0 {
		return nil, fmt.Errorf("logging: register event source: %w", callErr)
	}
	return &eventLogWriter{handle: h}, nil
}

func (w *eventLogWriter) close() {
	if w != nil && w.handle != 0 {
		procDeregisterEventSource.Call(w.handle)
		w.handle = 0
	}
}

// write emits one event.
//
// Failures are returned rather than swallowed, but callers generally ignore
// them: an agent that cannot write to the Event Log must keep serving, and it
// still has its structured JSON log.
func (w *eventLogWriter) write(eventType uint16, message string) error {
	if w == nil || w.handle == 0 {
		return nil
	}
	msgPtr, err := syscall.UTF16PtrFromString(message)
	if err != nil {
		return err
	}
	strings := []*uint16{msgPtr}

	r, _, callErr := procReportEventW.Call(
		w.handle,
		uintptr(eventType),
		0, // category
		genericEventID,
		0, // user SID
		1, // number of insertion strings
		0, // raw data size
		uintptr(unsafe.Pointer(&strings[0])),
		0, // raw data
	)
	if r == 0 {
		return fmt.Errorf("logging: report event: %w", callErr)
	}
	return nil
}

func registerSource(source string) error   { return registerEventSource(source) }
func deregisterSource(source string) error { return deregisterEventSource(source) }
func newEventSink(source string) (eventSink, error) {
	w, err := openEventLog(source)
	if err != nil {
		return nil, err
	}
	return w, nil
}

// Satisfy the eventSink interface declared in logging.go.
func (w *eventLogWriter) Info(msg string) error  { return w.write(eventLogInformation, msg) }
func (w *eventLogWriter) Warn(msg string) error  { return w.write(eventLogWarning, msg) }
func (w *eventLogWriter) Error(msg string) error { return w.write(eventLogError, msg) }
func (w *eventLogWriter) Close() error           { w.close(); return nil }
