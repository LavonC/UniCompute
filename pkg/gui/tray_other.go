//go:build !windows

package gui

// TrayManager fallback stub for non-Windows platforms.
type TrayManager struct{}

func NewTrayManager(hwnd uintptr) *TrayManager {
	return &TrayManager{}
}

func (t *TrayManager) Install(initialTip string) error {
	return nil
}

func (t *TrayManager) UpdateTooltip(tip string) error {
	return nil
}

func (t *TrayManager) ShowBalloon(title, message string) error {
	return nil
}

func (t *TrayManager) RestoreWindow() {}

func (t *TrayManager) MinimizeToTray() {}

func (t *TrayManager) Remove() error {
	return nil
}
