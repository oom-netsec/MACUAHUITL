package diag

import (
	"strings"
	"testing"
)

// 3.4: TEMP/TMP vacíos, relativos, UNC o de dispositivo no llegan al hijo: se reemplazan por %LOCALAPPDATA%\Temp y, sin una
// LOCALAPPDATA válida, se quitan (nunca C:\Windows\Temp ni una carpeta de red).
func TestWinChildEnvTempHostil(t *testing.T) {
	malos := []string{"", "tmp", `\Temp`, `C:Temp`, `C:`, `\\host\share\t`, `//host/share/t`, `\\?\C:\t`, `\\.\C:\t`, `C:\a\..\b`, `C:/a`, `C:\a\\b`}
	for _, v := range malos {
		for _, k := range []string{"TEMP", "TMP"} {
			e := map[string]string{"SystemRoot": `C:\Windows`, k: v, "LOCALAPPDATA": `D:\Datos\Local`}
			got := strings.Join(winChildEnv(env(e), `C:\x\a.exe`), "|")
			if v != "" && strings.Contains(got, k+"="+v+"|") {
				t.Errorf("%s=%q llegó al hijo: %s", k, v, got)
			}
			if !strings.Contains(got, `TEMP=D:\Datos\Local\Temp`) && !strings.Contains(got, `TMP=D:\Datos\Local\Temp`) {
				t.Errorf("%s=%q: sin el reemplazo de LOCALAPPDATA: %s", k, v, got)
			}
			e["LOCALAPPDATA"] = ""
			if got := strings.Join(winChildEnv(env(e), `C:\x\a.exe`), "|"); strings.Contains(got, "TEMP=") || strings.Contains(got, "TMP=") {
				t.Errorf("%s=%q sin LOCALAPPDATA debe quitarse: %s", k, v, got)
			}
		}
	}
	// 3.3: una LOCALAPPDATA en otra unidad o con nombre corto 8.3 es válida y se usa tal cual.
	e := map[string]string{"SystemRoot": `C:\Windows`, "TEMP": "", "LOCALAPPDATA": `E:\USERS\ANA~1\AppData\Local`}
	if got := strings.Join(winChildEnv(env(e), `C:\x\a.exe`), "|"); !strings.Contains(got, `TEMP=E:\USERS\ANA~1\AppData\Local\Temp`) {
		t.Errorf("otra unidad: %s", got)
	}
}
