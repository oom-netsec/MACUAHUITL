# Fase 6 — Release: Plan de implementación

**Goal:** Paquetes `.deb` y `.rpm` instalables, compilación reproducible verificable por un tercero, SBOM y sumas firmadas en cada release, y la guía de auditoría completada con los comandos reales.

**Architecture:** `deploy/packaging/nfpm.yaml` describe los paquetes (binarios, unidad systemd de usuario, archivo `.desktop`, documentación). `Taskfile` tiene `release-build` (binarios reproducibles) y `package`. El workflow `release.yml` corre al etiquetar `v*`: compila, verifica reproducibilidad, empaqueta, genera SBOM, calcula SHA-256 y publica el release. Sin telemetría, sin actualizaciones automáticas (spec §2).

**Tech Stack:** nfpm v2.48.0, `anchore/sbom-action` v0.24.3, `softprops/action-gh-release` v3.0.3.

**Spec:** `docs/architecture/2026-11-02-macuahuitl-architecture-design.md` §10.5, §17 (fase 6); `docs/security/AUDIT_GUIDE.md` §5.

## Global Constraints

- Núcleo y CLI con `CGO_ENABLED=0 -trimpath -ldflags "-s -w -buildid= -X …version.Version=<tag>"`: dos compilaciones dan el mismo SHA-256.
- La UI se compila con `-tags 'wails gtk3'` y cgo: no es reproducible byte a byte (depende de las librerías del sistema); se publica su SHA-256 igual, con nota.
- El paquete instala en `/usr/bin`, la unidad en `/usr/lib/systemd/user/`, y recomienda (no exige) `nmap`, `iperf3`, `wireshark-common`.
- Versión del paquete = tag sin la `v`.

## Review Focus

1. **`dpkg -i` en un sistema limpio** deja `macuahuitld`, `mctl`, `macuahuitl` ejecutables y `systemctl --user enable --now macuahuitld` funciona. Test en Task 1 (contenido del .deb).
2. **Dos compilaciones del núcleo** dan la misma suma. Test en Task 1.
3. **El tag `v1.2.3`** produce versión `1.2.3` en el paquete y `macuahuitl v1.2.3` en `--version`. Test en Task 1.

---

### Task 1: nfpm, Taskfile y prueba de contenido
**Files:** `deploy/packaging/nfpm.yaml`, `deploy/packaging/macuahuitl.desktop`, `deploy/packaging/postinstall.sh`, `Taskfile.yml`, `deploy/packaging/package_test.go` (construye el .deb con nfpm y revisa su contenido con `dpkg-deb -c`).

### Task 2: Workflow de release
**Files:** `.github/workflows/release.yml`, `docs/security/AUDIT_GUIDE.md` (§5 con los comandos reales), `deploy/packaging/README.md`.
