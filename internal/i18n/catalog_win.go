package i18n

// Variantes de Windows (ADR 0012): Msg las usa en lugar del código base cuando el núcleo corre en Windows. Mismo código
// y mismos argumentos que la versión de Linux; solo cambia lo que nombra algo de Linux. (El nombre del archivo no
// termina en _windows.go a propósito: Go lo compilaría solo en Windows y las pruebas de Linux no lo verían.)
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		// En Windows un COM abierto por otra app da ERROR_ACCESS_DENIED o ERROR_SHARING_VIOLATION: serialcon lo reporta como
		// «en uso» (serial.err.busy), igual que en Linux; no hay grupo dialout ni permiso que dar.
		"serial.err.busy.windows": e(
			"serialcon: {path} está en uso por otra aplicación (otra terminal serie como PuTTY, o el software del adaptador): ciérrala y vuelve a intentarlo",
			"serialcon: {path} is in use by another application (another serial terminal such as PuTTY, or the adapter's software): close it and try again",
			"path"),
		"mctl.field.no_adapters.windows": e(
			"no hay adaptadores USB-serie conectados (puertos COM); revisa el Administrador de dispositivos → Puertos (COM y LPT): si el adaptador no aparece, falta su controlador",
			"no USB-serial adapters connected (COM ports); check Device Manager → Ports (COM & LPT): if the adapter is not listed, its driver is missing"),
		"mctl.field.many_ports.windows": e(
			"hay varios puertos: indica cuál, p. ej. mctl console COM3",
			"there are several ports: say which one, e.g. mctl console COM3"),
	})
}
