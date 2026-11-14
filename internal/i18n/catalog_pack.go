package i18n

// Paquetes de contenido (fase 32, ADR 0010): motivos de rechazo de un .mpack (pack.err.*), errores del almacén y del
// servicio, y pack.missing (un trabajo pide un playbook que vive en un paquete no instalado). El motivo estable es el código.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"pack.err.signature.invalid":  e("la firma del paquete no es válida", "the package signature is not valid"),
		"pack.err.zip.invalid":        e("el archivo no es un zip legible", "the file is not a readable zip"),
		"pack.err.zip.path":           e("ruta no permitida en el paquete: {name:q}", "path not allowed in the package: {name:q}", "name"),
		"pack.err.zip.dup":            e("entrada repetida en el paquete: {name:q}", "repeated entry in the package: {name:q}", "name"),
		"pack.err.zip.too_big":        e("el paquete pasa de un tope ({what})", "the package exceeds a limit ({what})", "what"),
		"pack.err.zip.missing":        e("al paquete le falta {name}", "the package is missing {name}", "name"),
		"pack.err.index.mismatch":     e("el contenido no coincide con su índice: {name:q}", "the content does not match its index: {name:q}", "name"),
		"pack.err.manifest.invalid":   e("manifiesto inválido en {field}", "invalid manifest in {field}", "field"),
		"pack.err.core.too_old":       e("el paquete pide el núcleo {min_core} o más nuevo y este es {core}", "the package needs core {min_core} or newer and this is {core}", "min_core", "core"),
		"pack.err.playbook.denied":    e("un playbook trae un comando que no es de lectura: {cause}", "a playbook has a command that is not read-only: {cause}", "cause"),
		"pack.err.playbook.invalid":   e("playbook inválido: {cause}", "invalid playbook: {cause}", "cause"),
		"pack.err.playbook.platform":  e("el playbook {id} es de la plataforma {platform}, que no se acepta o no está en platforms del manifiesto", "playbook {id} is for platform {platform}, which is not accepted or not in the manifest platforms", "id", "platform"),
		"pack.err.script.invalid":     e("script inválido: {cause}", "invalid script: {cause}", "cause"),
		"pack.err.id.prefix":          e("el ID {id:q} de un paquete de terceros debe empezar con {want:q}", "the ID {id:q} in a third-party package must start with {want:q}", "id", "want"),
		"pack.err.editor.reserved":    e("el editor {editor:q} es solo de paquetes con firma oficial", "the publisher {editor:q} is reserved for packages with an official signature", "editor"),
		"pack.err.read":               e("no se pudo leer el paquete: {cause}", "the package could not be read: {cause}", "cause"),
		"pack.err.unsigned":           e("el paquete no está firmado; confirma la instalación de un paquete de terceros", "the package is not signed; confirm the installation of a third-party package"),
		"pack.err.collision":          e("{id} ya existe en {with}", "{id} already exists in {with}", "id", "with"),
		"pack.err.version":            e("ya está instalada la versión {installed} de {id}; quítala antes de instalar la {version}", "version {installed} of {id} is already installed; remove it before installing {version}", "id", "installed", "version"),
		"pack.err.official_replace":   e("el paquete oficial {id} solo lo reemplaza otro con firma oficial", "the official package {id} can only be replaced by another with an official signature", "id"),
		"pack.err.not_found":          e("no hay un paquete {id:q} instalado", "there is no installed package {id:q}", "id"),
		"pack.err.path":               e("indica la ruta de un archivo .mpack", "give the path of an .mpack file"),
		"pack.err.item":               e("{id:q} no es un playbook ni un script de {pack}, o está en hide y show a la vez", "{id:q} is not a playbook or script of {pack}, or it is in both hide and show", "id", "pack"),
		"pack.err.items_empty":        e("indica al menos un elemento para ocultar o mostrar", "give at least one item to hide or show"),
		"pack.err.export.empty":       e("no hay nada que exportar: elige scripts o playbooks exportables", "there is nothing to export: choose scripts or exportable playbooks"),
		"pack.err.export.name_dup":    e("dos elementos del paquete se llaman igual: {name:q}", "two items in the package have the same name: {name:q}", "name"),
		"pack.err.import.official":    e("un paquete con firma oficial se instala, no se importa", "a package with an official signature is installed, not imported"),
		"pack.err.import.missing":     e("falta decidir qué hacer con {id}: renombrar u omitir", "a decision is missing for {id}: rename or skip", "id"),
		"pack.err.import.decision":    e("decisión no válida para {id}: solo renombrar (si choca) u omitir, y el ID debe ser del paquete", "invalid decision for {id}: only rename (on a clash) or skip, and the ID must be in the package", "id"),
		"pack.err.import.exists":      e("el archivo {file} ya existe; no se sobrescribe", "the file {file} already exists; it is not overwritten", "file"),
		"pack.err.import.changed":     e("el archivo cambió desde la vista previa; vuelve a revisarlo", "the file changed since the preview; review it again"),
		"pack.err.import.unavailable": e("este núcleo no tiene carpeta de configuración para guardar playbooks", "this core has no configuration folder to store playbooks"),
		"pack.err.export.range":       e("se exportan hasta {max} scripts", "export up to {max} scripts", "max"),
		"pack.err.script.platform":    e("script {id}: plataforma {platform:q} fuera de platforms del manifiesto", "script {id}: platform {platform:q} is not in the manifest platforms", "id", "platform"),
		"pack.err.script.origin":      e("script {id}: origin biblioteca e ID lib-… obligatorios", "script {id}: origin \"biblioteca\" and a lib-... ID are required", "id"),
		"pack.err.playbook.id":        e("playbook {id}: el id debe ser a-z, 0-9 y guion, e igual al nombre del archivo {file}", "playbook {id}: the id must be a-z, 0-9 and hyphen, and equal to the file name {file}", "id", "file"),
		"pack.missing":                e("el playbook {playbook} viene en el paquete {pack}, que no está instalado; instálalo con «mctl pack install»", "playbook {playbook} comes in package {pack}, which is not installed; install it with \"mctl pack install\"", "playbook", "pack"),
	})
}
