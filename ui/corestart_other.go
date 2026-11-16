//go:build wails && !windows

package main

import "github.com/oom-netsec/MACUAHUITL/ui/bridge"

// coreLauncher: fuera de Windows el núcleo es un servicio de usuario de systemd; la app no lo arranca.
func coreLauncher() *bridge.CoreLauncher { return nil }
