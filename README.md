# inotify-watch — Monitor de eventos del sistema de archivos de Linux (C++23)

`inotify-watch` es un monitor de eventos del sistema de archivos escrito en **C++23** sin dependencias externas. Usa la API `inotify(7)` del kernel de Linux para vigilar directorios y archivos en tiempo real: creaciones, modificaciones, cambios de metadatos, renames (con pairing por cookie), eliminaciones y más — con máscara configurable, modo recursivo, salida JSON por línea y 30 tests de auto-verificación.

## Características

- **15 tipos de eventos inotify** decodificados: CREATE, MODIFY, ATTRIB, DELETE, MOVED_FROM/MOVED_TO, OPEN, ACCESS, CLOSE_WRITE/CLOSE_NOWRITE, DELETE_SELF, MOVE_SELF, UNMOUNT, Q_OVERFLOW e IGNORED.
- **Pairing de renames por cookie**: los eventos MOVED_FROM + MOVED_TO se emparejan vía el campo `cookie` del kernel (único por rename) y se muestran como una sola línea `RENAME a.txt -> b.txt`.
- **Watch recursivo** (`-r`): inotify no es recursivo por naturaleza — la herramienta escanea el árbol con `std::filesystem` y registra un watch por directorio, saltando permisos denegados sin abortar el scan.
- **Máscara configurable** (`-m`): `create, modify, delete, move, attrib, open, close, access, all`.
- **Detección de directorios**: el flag `IN_ISDIR` se marca en cada evento (línea `dir` en negrita).
- **Salida JSON por línea** (`--json`) para scripting: `{"ts":...,"type":"CREATE","path":"...","dir":false,"cookie":0}`.
- **RAII sobre el fd de inotify** con `std::expected` (C++23) para manejo de errores sin excepciones; loop con `poll()` de 500ms que responde a Ctrl+C y `--timeout N`.
- **`--demo`**: flujo sintético realista (build de una app) para contenedores/VMs y capturas.
- **`--selftest`**: 30 checks de auto-verificación sobre eventos reales (create/modify/attrib/rename/delete, pairing, filtro de máscara, remove, watch de archivo, recursivo, JSON).
- **Cero dependencias**: compilación directa con `g++ -std=c++23`.

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o inotify-watch
```

## Uso

```bash
./inotify-watch                       # vigila . con la máscara por defecto
./inotify-watch -r src docs           # vigila dos árboles recursivamente
./inotify-watch --mask create,delete /tmp
./inotify-watch --json -t 10 /var/log # 10s de eventos como JSONL
./inotify-watch --demo                # flujo sintético
./inotify-watch --no-color            # sin ANSI (pipes/logs)
./inotify-watch --selftest            # 30 auto-checks
```

### Ejemplo de salida

```
$ ./inotify-watch -r src
•  watching src (recursive, 4 dirs)
INOTIFY WATCH — filesystem events (inotify(7))
mask: CREATE|MODIFY|DELETE|MOVE|ATTRIB · Ctrl+C para salir
[11:42:03] CREATE     dir  src/components
[11:42:04] CREATE     file src/components/Button.tsx
[11:42:04] MODIFY     file src/components/Button.tsx
[11:42:05] ATTRIB     file src/components/Button.tsx
[11:42:07] RENAME     file src/components/Button.tsx -> src/components/Button.tsx.bak
[11:42:08] CREATE     file src/components/Button.tsx
[11:42:09] MODIFY     file src/components/Button.tsx
[11:42:14] DELETE     file src/components/Button.tsx.bak
[11:42:15] DELETE     file tmp/cache-0.tmp
SUMMARY  watched 1 path(s) · 18 events in 15.3s · ATTRIB 1  CREATE 7  DELETE 2  MODIFY 6  RENAME 1
```

### JSON

```json
{"ts":1786849781,"type":"CREATE","path":"/var/log/nginx/access.log","dir":false,"cookie":0}
{"ts":1786849782,"type":"MODIFY","path":"/var/log/nginx/access.log","dir":false,"cookie":0}
{"ts":1786849783,"type":"RENAME","from":"/var/log/nginx/access.log","to":"/var/log/nginx/access.log.1","dir":false,"cookie":2559871}
```

## Cómo funciona

- `inotify_init1(IN_NONBLOCK)` crea el descriptor; `inotify_add_watch(path, mask)` registra un watch por ruta; los eventos se leen con `read()` en batches de 64KB y se decodifican los `inotify_event` (wd, mask, cookie, name).
- El `cookie` de MOVED_FROM/MOVED_TO identifica un mismo rename: se emparejan y se imprimen como una línea `RENAME`.
- inotify no es recursivo: `-r` escanea el árbol con `recursive_directory_iterator` (con `skip_permission_denied` y limpieza de `error_code` por iteración) y registra un watch por directorio.
- La cola se drena en modo no bloqueante (`EAGAIN` = fin); el loop principal usa `poll()` con timeout de 500ms para responder a Ctrl+C / `--timeout`.

## Tests

```bash
./inotify-watch --selftest
# 30 passed, 0 failed
```

## Licencia

MIT — SPDX-License-Identifier: MIT
