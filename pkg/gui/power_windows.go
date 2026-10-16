//go:build windows

package gui

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SYSTEM_POWER_STATUS corresponds to the Win32 structure returned by GetSystemPowerStatus.
type SYSTEM_POWER_STATUS struct {
	ACLineStatus        byte // 0: Offline (battery), 1: Online (AC), 255: Unknown
	BatteryFlag         byte // 1: High, 2: Low, 4: Critical, 8: Charging, 128: No battery, 255: Unknown
	BatteryLifePercent  byte // 0-100, 255: Unknown
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

var (
	modKernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemPowerStatus = modKernel32.NewProc("GetSystemPowerStatus")
)

// QuerySystemPower checks Windows power status via GetSystemPowerStatus.
func QuerySystemPower() (onBattery bool, batteryPercent int, powerSource string, err error) {
	var sps SYSTEM_POWER_STATUS
	r, _, callErr := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&sps)))
	if r == 0 {
		return false, 100, "AC (Mains Power)", fmt.Errorf("GetSystemPowerStatus call failed: %w", callErr)
	}

	onBattery = (sps.ACLineStatus == 0)
	pct := int(sps.BatteryLifePercent)
	if pct > 100 {
		pct = 100
	}

	source := "AC (Mains Power)"
	if onBattery {
		source = "DC Battery Power"
	} else if sps.ACLineStatus == 255 {
		source = "AC (Detected)"
	}

	return onBattery, pct, source, nil
}
