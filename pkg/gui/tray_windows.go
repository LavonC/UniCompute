//go:build windows

package gui

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	NIM_ADD     = 0x00000000
	NIM_MODIFY  = 0x00000001
	NIM_DELETE  = 0x00000002

	NIF_MESSAGE = 0x00000001
	NIF_ICON    = 0x00000002
	NIF_TIP     = 0x00000004
	NIF_INFO    = 0x00000010

	NIIF_INFO   = 0x00000001

	WM_USER     = 0x0400
	WM_TRAYICON = WM_USER + 200

	IDI_APPLICATION = 32512
	SW_HIDE         = 0
	SW_SHOW         = 5
	SW_RESTORE      = 9
)

// NOTIFYICONDATAW represents the Win32 notification icon structure.
type NOTIFYICONDATAW struct {
	CbSize           uint32
	HWnd             windows.HWND
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	TimeoutOrVersion uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

var (
	modShell32             = windows.NewLazySystemDLL("shell32.dll")
	procShell_NotifyIconW  = modShell32.NewProc("Shell_NotifyIconW")

	modUser32              = windows.NewLazySystemDLL("user32.dll")
	procLoadIconW          = modUser32.NewProc("LoadIconW")
	procShowWindow         = modUser32.NewProc("ShowWindow")
	procSetForegroundWindow= modUser32.NewProc("SetForegroundWindow")
	modComctl32            = windows.NewLazySystemDLL("comctl32.dll")
	procSetWindowSubclass  = modComctl32.NewProc("SetWindowSubclass")
	procRemoveWindowSubclass = modComctl32.NewProc("RemoveWindowSubclass")
	procDefSubclassProc    = modComctl32.NewProc("DefSubclassProc")
)

var traySubclassCallback = syscall.NewCallback(func(hwnd uintptr, msg uint32, wParam, lParam, uIdSubclass, dwRefData uintptr) uintptr {
	if msg == WM_TRAYICON {
		// 0x0202: WM_LBUTTONUP, 0x0203: WM_LBUTTONDBLCLK, 0x0205: WM_RBUTTONUP
		if lParam == 0x0202 || lParam == 0x0203 || lParam == 0x0205 {
			procShowWindow.Call(hwnd, uintptr(SW_RESTORE))
			procSetForegroundWindow.Call(hwnd)
			return 0
		}
	}
	r, _, _ := procDefSubclassProc.Call(hwnd, uintptr(msg), wParam, lParam)
	return r
})

// TrayManager manages the Windows System Tray icon, tooltips, and balloon alerts.
type TrayManager struct {
	mu        sync.Mutex
	hwnd      windows.HWND
	hIcon     windows.Handle
	installed bool
}

// NewTrayManager creates a new System Tray manager for a window handle.
func NewTrayManager(hwnd uintptr) *TrayManager {
	tm := &TrayManager{
		hwnd: windows.HWND(hwnd),
	}

	// Load standard application icon
	hIcon, _, _ := procLoadIconW.Call(0, uintptr(IDI_APPLICATION))
	tm.hIcon = windows.Handle(hIcon)

	return tm
}

// Install registers the icon in the Windows taskbar notification area.
func (t *TrayManager) Install(initialTip string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = t.hwnd
	nid.UID = 1001
	nid.UFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
	nid.UCallbackMessage = WM_TRAYICON
	nid.HIcon = t.hIcon

	if initialTip == "" {
		initialTip = "UniCompute Studio (Active)"
	}
	tipUTF16, _ := syscall.UTF16FromString(initialTip)
	copy(nid.SzTip[:], tipUTF16)

	ret, _, err := procShell_NotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(&nid)))
	if ret == 0 {
		return fmt.Errorf("failed to register system tray icon: %w", err)
	}

	if t.hwnd != 0 {
		procSetWindowSubclass.Call(uintptr(t.hwnd), traySubclassCallback, 1001, 0)
	}

	t.installed = true
	return nil
}

// UpdateTooltip updates the text displayed on hovering over the tray icon.
func (t *TrayManager) UpdateTooltip(tip string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.installed {
		return nil
	}

	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = t.hwnd
	nid.UID = 1001
	nid.UFlags = NIF_TIP

	tipUTF16, _ := syscall.UTF16FromString(tip)
	copy(nid.SzTip[:], tipUTF16)

	ret, _, err := procShell_NotifyIconW.Call(NIM_MODIFY, uintptr(unsafe.Pointer(&nid)))
	if ret == 0 {
		return fmt.Errorf("failed to update tray tooltip: %w", err)
	}
	return nil
}

// ShowBalloon displays a desktop notification balloon from the system tray.
func (t *TrayManager) ShowBalloon(title, message string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.installed {
		return nil
	}

	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = t.hwnd
	nid.UID = 1001
	nid.UFlags = NIF_INFO
	nid.DwInfoFlags = NIIF_INFO

	titleUTF16, _ := syscall.UTF16FromString(title)
	copy(nid.SzInfoTitle[:], titleUTF16)

	msgUTF16, _ := syscall.UTF16FromString(message)
	copy(nid.SzInfo[:], msgUTF16)

	ret, _, err := procShell_NotifyIconW.Call(NIM_MODIFY, uintptr(unsafe.Pointer(&nid)))
	if ret == 0 {
		return fmt.Errorf("failed to show tray notification balloon: %w", err)
	}
	return nil
}

// RestoreWindow restores the associated window and brings it to the foreground.
func (t *TrayManager) RestoreWindow() {
	if t.hwnd != 0 {
		procShowWindow.Call(uintptr(t.hwnd), uintptr(SW_RESTORE))
		procSetForegroundWindow.Call(uintptr(t.hwnd))
	}
}

// MinimizeToTray hides the associated window into the system tray.
func (t *TrayManager) MinimizeToTray() {
	if t.hwnd != 0 {
		procShowWindow.Call(uintptr(t.hwnd), uintptr(SW_HIDE))
	}
}

// Remove removes the icon from the system tray upon exit.
func (t *TrayManager) Remove() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.installed {
		return nil
	}

	var nid NOTIFYICONDATAW
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = t.hwnd
	nid.UID = 1001

	if t.hwnd != 0 {
		procRemoveWindowSubclass.Call(uintptr(t.hwnd), traySubclassCallback, 1001)
	}

	ret, _, err := procShell_NotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&nid)))
	t.installed = false
	if ret == 0 {
		return fmt.Errorf("failed to remove tray icon: %w", err)
	}
	return nil
}
