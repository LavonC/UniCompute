//go:build !windows

package gui

// QuerySystemPower fallback for non-Windows platforms.
func QuerySystemPower() (onBattery bool, batteryPercent int, powerSource string, err error) {
	return false, 100, "AC (Mains Power)", nil
}
