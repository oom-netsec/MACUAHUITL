package sys

// SyncDir no hace nada en Windows y devuelve nil. os.Open(carpeta).Sync() da «Access is denied»: FlushFileBuffers sobre
// un directorio exige un handle con escritura y FILE_FLAG_BACKUP_SEMANTICS, y aun así no tiene durabilidad documentada.
// NTFS registra el rename y la creación de archivos en su journal de metadatos; lo que sí hay que sincronizar es el
// contenido de cada archivo (File.Sync), y eso sigue haciéndose.
func SyncDir(string) error { return nil }
