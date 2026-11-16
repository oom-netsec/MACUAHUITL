package i18n

// Variantes de Windows (ADR 0012): Msg las usa en lugar del código base cuando el núcleo corre en Windows. Mismo código
// y mismos argumentos que la versión de Linux; solo cambia lo que nombra algo de Linux. (El nombre del archivo no
// termina en _windows.go a propósito: Go lo compilaría solo en Windows y las pruebas de Linux no lo verían.)
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"serial.err.permission_hint.windows": e(
			"{cause} {path}: el puerto está en uso por otra aplicación (otra terminal serie, el software del adaptador). Ciérrala y vuelve a intentarlo",
			"{cause} {path}: the port is in use by another application (another serial terminal, the adapter's software). Close it and try again",
			"cause", "path"),
		"mctl.field.no_adapters.windows": e(
			"no hay adaptadores USB-serie conectados (puertos COM); revisa el Administrador de dispositivos → Puertos (COM y LPT): si el adaptador no aparece, falta su controlador",
			"no USB-serial adapters connected (COM ports); check Device Manager → Ports (COM & LPT): if the adapter is not listed, its driver is missing"),
		"mctl.field.many_ports.windows": e(
			"hay varios puertos: indica cuál, p. ej. mctl console COM3",
			"there are several ports: say which one, e.g. mctl console COM3"),
	})
}
