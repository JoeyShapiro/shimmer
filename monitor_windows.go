//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	kernelFileProviderGUID = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"

	wnodeFlagTracedGuid        = 0x00020000
	eventTraceRealTimeMode     = 0x00000100
	processTraceModeRealTime   = 0x00000100
	processTraceModeEventRecord = 0x10000000
	eventControlCodeEnable     = 1
	traceLevelVerbose          = 5
	eventTraceControlStop      = 1

	errAlreadyExists       = 0xB7
	errInsufficientBuffer  = 0x7A
)

var (
	advapi32             = windows.NewLazySystemDLL("advapi32.dll")
	tdh                  = windows.NewLazySystemDLL("tdh.dll")
	procStartTrace       = advapi32.NewProc("StartTraceW")
	procEnableTraceEx2   = advapi32.NewProc("EnableTraceEx2")
	procOpenTrace        = advapi32.NewProc("OpenTraceW")
	procProcessTrace     = advapi32.NewProc("ProcessTrace")
	procControlTrace     = advapi32.NewProc("ControlTraceW")
	procCloseTrace       = advapi32.NewProc("CloseTrace")
	procTdhGetProperty   = tdh.NewProc("TdhGetProperty")
)

// etwProps maps to EVENT_TRACE_PROPERTIES + appended session name buffer.
// Layout verified for Windows 10 x64.
// WNODE_HEADER (48 bytes) + EVENT_TRACE_PROPERTIES fields (72 bytes) = 120 bytes.
type etwProps struct {
	// WNODE_HEADER
	WnodeSize      uint32
	WnodeProvId    uint32
	WnodeVersion   uint64
	WnodeClock     uint64
	WnodeGuid      windows.GUID
	WnodeClientCtx uint32
	WnodeFlags     uint32
	// EVENT_TRACE_PROPERTIES
	BufferSize      uint32
	MinBuffers      uint32
	MaxBuffers      uint32
	MaxFileSize     uint32
	LogFileMode     uint32
	FlushTimer      uint32
	EnableFlags     uint32
	AgeLimit        int32
	NumBuffers      uint32
	FreeBuffers     uint32
	EventsLost      uint32
	BuffersWritten  uint32
	LogBufLost      uint32
	RtBufLost       uint32
	LoggerThreadId  windows.Handle // uintptr-sized HANDLE
	LogFileNameOff  uint32
	LoggerNameOff   uint32
}

// propertyDataDescriptor maps to PROPERTY_DATA_DESCRIPTOR.
// PropertyName is a ULONGLONG holding a pointer to a WCHAR string.
type propertyDataDescriptor struct {
	PropertyName uint64
	ArrayIndex   uint32
	Reserved     uint32
}

// monitorBinary launches targetPath then subscribes to the Kernel-File ETW
// provider and prints file I/O events for that process to stdout.
// Requires Administrator privileges on Windows.
func monitorBinary(targetPath string) error {
	absPath, err := exec.LookPath(targetPath)
	if err != nil {
		return fmt.Errorf("cannot find binary: %w", err)
	}

	cmd := exec.Command(absPath, os.Args[3:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start target: %w", err)
	}
	targetPID := uint32(cmd.Process.Pid)
	fmt.Printf("[monitor] started %s (PID %d)\n", absPath, targetPID)

	const sessionName = "shmitm-monitor"

	sessionHandle, err := startEtwSession(sessionName)
	if err != nil {
		cmd.Process.Kill()
		return err
	}
	defer stopEtwSession(sessionName)

	if err := enableKernelFileProvider(sessionHandle); err != nil {
		cmd.Process.Kill()
		return err
	}

	traceHandle, err := openEtwConsumer(sessionName, targetPID)
	if err != nil {
		cmd.Process.Kill()
		return err
	}

	traceDone := make(chan error, 1)
	go func() {
		r, _, _ := procProcessTrace.Call(uintptr(unsafe.Pointer(&traceHandle)), 1, 0, 0)
		if r != 0 && r != 0x1C8 { // 0x1C8 = ERROR_CTX_CLOSE_PENDING, normal on stop
			traceDone <- fmt.Errorf("ProcessTrace error: 0x%x", r)
		} else {
			traceDone <- nil
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	procDone := make(chan error, 1)
	go func() { procDone <- cmd.Wait() }()

	select {
	case <-sigCh:
		fmt.Println("\n[monitor] interrupted")
		cmd.Process.Kill()
	case err := <-procDone:
		if err != nil {
			fmt.Printf("[monitor] process exited: %v\n", err)
		} else {
			fmt.Println("[monitor] process exited cleanly")
		}
	}

	procCloseTrace.Call(uintptr(traceHandle))
	<-traceDone
	return nil
}

func startEtwSession(sessionName string) (uint64, error) {
	sessionNamePtr, _ := windows.UTF16PtrFromString(sessionName)

	const extraBytes = 512
	propsSize := uint32(unsafe.Sizeof(etwProps{})) + extraBytes
	buf := make([]byte, propsSize)
	p := (*etwProps)(unsafe.Pointer(&buf[0]))
	p.WnodeSize = propsSize
	p.WnodeFlags = wnodeFlagTracedGuid
	p.LogFileMode = eventTraceRealTimeMode
	p.LoggerNameOff = uint32(unsafe.Sizeof(etwProps{}))

	var handle uint64
	r, _, _ := procStartTrace.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(sessionNamePtr)),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if r == errAlreadyExists {
		// Stop leftover session from a previous run and retry.
		stopEtwSession(sessionName)
		r, _, _ = procStartTrace.Call(
			uintptr(unsafe.Pointer(&handle)),
			uintptr(unsafe.Pointer(sessionNamePtr)),
			uintptr(unsafe.Pointer(&buf[0])),
		)
	}
	if r != 0 {
		return 0, fmt.Errorf("StartTrace failed (0x%x) — run as Administrator", r)
	}
	return handle, nil
}

func stopEtwSession(sessionName string) {
	sessionNamePtr, _ := windows.UTF16PtrFromString(sessionName)
	const extraBytes = 512
	propsSize := uint32(unsafe.Sizeof(etwProps{})) + extraBytes
	buf := make([]byte, propsSize)
	p := (*etwProps)(unsafe.Pointer(&buf[0]))
	p.WnodeSize = propsSize
	p.WnodeFlags = wnodeFlagTracedGuid
	p.LoggerNameOff = uint32(unsafe.Sizeof(etwProps{}))
	procControlTrace.Call(0, uintptr(unsafe.Pointer(sessionNamePtr)),
		uintptr(unsafe.Pointer(&buf[0])), eventTraceControlStop)
}

func enableKernelFileProvider(sessionHandle uint64) error {
	guid, err := windows.GUIDFromString(kernelFileProviderGUID)
	if err != nil {
		return fmt.Errorf("invalid provider GUID: %w", err)
	}
	r, _, _ := procEnableTraceEx2.Call(
		uintptr(sessionHandle),
		uintptr(unsafe.Pointer(&guid)),
		eventControlCodeEnable,
		traceLevelVerbose,
		0xFFFFFFFFFFFFFFFF, // MatchAnyKeyword — all
		0,                   // MatchAllKeyword
		0,                   // Timeout
		0,                   // EnableParameters
	)
	if r != 0 {
		return fmt.Errorf("EnableTraceEx2 failed (0x%x)", r)
	}
	return nil
}

// openEtwConsumer opens a real-time ETW consumer for the given session and
// wires up the event-record callback filtered to targetPID.
//
// EVENT_TRACE_LOGFILE layout on Windows 10 x64 (byte offsets):
//   0   LogFileName        *uint16
//   8   LoggerName         *uint16
//   16  CurrentTime        int64
//   24  BuffersRead        uint32
//   28  ProcessTraceMode   uint32   ← union with LogFileMode
//   32  CurrentEvent       [88]byte  (EVENT_TRACE)
//   120 LogfileHeader      [304]byte (TRACE_LOGFILE_HEADER)
//   424 BufferCallback     uintptr
//   432 BufferSize         uint32
//   436 Filled             uint32
//   440 EventsLost         uint32
//   444 (padding)          uint32
//   448 EventCallback      uintptr   ← union with EventRecordCallback
//   456 IsKernelTrace      uint32
//   460 (padding)          uint32
//   464 Context            uintptr
func openEtwConsumer(sessionName string, targetPID uint32) (uint64, error) {
	loggerNamePtr, _ := windows.UTF16PtrFromString(sessionName)
	cbPtr := syscall.NewCallback(makeEventCallback(targetPID))

	const bufSize = 512
	buf := make([]byte, bufSize)

	// LoggerName at offset 8
	*(*uintptr)(unsafe.Pointer(&buf[8])) = uintptr(unsafe.Pointer(loggerNamePtr))
	// ProcessTraceMode at offset 28
	*(*uint32)(unsafe.Pointer(&buf[28])) = processTraceModeRealTime | processTraceModeEventRecord
	// EventRecordCallback at offset 448
	*(*uintptr)(unsafe.Pointer(&buf[448])) = cbPtr

	th, _, _ := procOpenTrace.Call(uintptr(unsafe.Pointer(&buf[0])))
	const invalidHandle = ^uint64(0)
	if th == uintptr(invalidHandle) {
		return 0, fmt.Errorf("OpenTrace failed — run as Administrator")
	}
	return uint64(th), nil
}

// makeEventCallback returns a Windows callback (stdcall/WINAPI) that receives
// a pointer to EVENT_RECORD and prints file I/O events for targetPID.
//
// Relevant offsets inside EVENT_RECORD on x64:
//   12  EventHeader.ProcessId         uint32
//   40  EventHeader.EventDescriptor.Id uint16
//   45  EventHeader.EventDescriptor.Opcode uint8
func makeEventCallback(targetPID uint32) func(uintptr) uintptr {
	return func(eventPtr uintptr) uintptr {
		pid := *(*uint32)(unsafe.Pointer(eventPtr + 12))
		if pid != targetPID {
			return 0
		}

		eventID := *(*uint16)(unsafe.Pointer(eventPtr + 40))

		var label string
		switch eventID {
		case 10:
			label = "OPEN"
		case 13:
			label = "READ"
		case 14:
			label = "WRITE"
		case 15:
			label = "SETINFO"
		case 16:
			label = "DELETE"
		case 17:
			label = "RENAME"
		default:
			return 0
		}

		path := tryStringProperty(eventPtr, "OpenPath")
		if path == "" {
			path = tryStringProperty(eventPtr, "FileName")
		}
		if path == "" {
			path = tryStringProperty(eventPtr, "FilePath")
		}
		if path == "" {
			return 0
		}

		fmt.Printf("[%s] %s\n", label, path)
		return 0
	}
}

// tryStringProperty calls TdhGetProperty to read a named UTF-16 string
// property from an EVENT_RECORD pointer. Returns "" on any error.
func tryStringProperty(eventPtr uintptr, name string) string {
	wname, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}
	desc := propertyDataDescriptor{
		PropertyName: uint64(uintptr(unsafe.Pointer(wname))),
		ArrayIndex:   ^uint32(0),
	}

	var buf [1024]byte
	r, _, _ := procTdhGetProperty.Call(
		eventPtr,
		0, 0,
		1,
		uintptr(unsafe.Pointer(&desc)),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if r != 0 {
		return ""
	}

	u16 := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), len(buf)/2)
	return windows.UTF16ToString(u16)
}
