# Cómo contribuir

- **Pruebas primero.** Todo cambio de comportamiento llega con una prueba que falló antes del cambio.
- **Red solo donde se permite.** El código de red vive en `internal/transport`, `internal/diag` e `internal/ipc`. `internal/sys` puede usar `golang.org/x/sys/unix` solo para endurecer el proceso. También pueden importar red `gen/` (código generado de gRPC, que va en el binario), `test/simulator` y `tools/` (estos dos no van en el binario). El analizador `noegress` corre en CI y rompe el build si otro paquete importa red, sockets de bajo nivel, cgo o ejecución de procesos.
- **`os.StartProcess`** lanza procesos sin importar `os/exec` y el analizador no lo ve. Está prohibido fuera de `internal/diag`; la revisión de código lo vigila.
- **Secretos.** Nunca uses `string` para un secreto fuera de `internal/secret`. Nunca registres un secreto, ni siquiera parcial.
- **Idioma.** Comentarios, documentación y mensajes al usuario en español. Identificadores en inglés.
- **Commits.** Formato `tipo(alcance): resumen` (`feat`, `fix`, `docs`, `chore`, `ci`, `test`).
- **Decisiones.** Un cambio de arquitectura llega con un ADR nuevo en `docs/adr/`.

Al contribuir aceptas que tu aporte se publique bajo la licencia [Apache-2.0](LICENSE) del proyecto.

Antes de abrir un PR:

```sh
task test
task lint
task proto-lint
```
