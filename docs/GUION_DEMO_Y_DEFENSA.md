# Guion de demo en vivo y defensa oral (BAC + SSRF)

## 0. Preparación (antes de presentar)

```bash
docker compose down -v && docker compose up --build     # frontend 5173 · API 8080 · Adminer 8081
git checkout main                                        # versión VULNERABLE para el ataque
```
Ten abiertas: una terminal, el navegador en http://localhost:5173 y DevTools. Plan B sin Docker: `cd backend && ./mvnw spring-boot:run` (MySQL en 3307).
Para pasar de "vulnerable" a "arreglado" solo cambias de rama y reinicias: `git checkout endurecimiento-u2 && docker compose up --build`.

---

## 1. Ataque BAC (≈ 2 min) — rama `main`

**A) Sin sesión, leer secretos**
```bash
curl -s http://localhost:8080/api/diagnostico | head -c 1500
```
Señala: `variablesEntorno`, `conexionBaseDatos` (`root` / `root123`) y `configuracionSecreta`.
```bash
curl -s http://localhost:8080/api/configuracion
curl -s http://localhost:8080/api/usuarios
```

**B) Cambiar el rol en el navegador**
1. Login `vendedor` / `vendedor` (no aparece el menú *Usuarios*).
2. DevTools → *Application → Local Storage → `pv_usuario`* → cambia `authorities` a `[{"authority":"ROL_ADMIN"}]` → F5.
3. Aparece *Usuarios* y se ve la lista: el servidor nunca preguntó quién eras.

**C) Hacerse admin sin permiso**
```bash
curl -s -X POST http://localhost:8080/api/auth/registro -H 'Content-Type: application/json' \
  -d '{"username":"intruso","password":"x","rol":"ADMIN"}'
```
La respuesta trae `"rol":"ADMIN"`.

## 2. Remediación BAC (≈ 2 min) — rama `endurecimiento-u2`

Muestra el diff: `SecurityConfig.java` (la regla `hasAuthority("ROL_ADMIN")`) y `AuthServicio.java` (`String rol = "VENDEDOR"`).

```bash
curl -i http://localhost:8080/api/diagnostico                          # 401 (sin sesión)
curl -i -u vendedor:vendedor http://localhost:8080/api/diagnostico     # 403 (sesión sin permiso)
curl -i -u admin:admin http://localhost:8080/api/diagnostico           # 200 (el admin sigue entrando)
curl -s -X POST http://localhost:8080/api/auth/registro -H 'Content-Type: application/json' \
  -d '{"username":"intruso2","password":"x","rol":"ADMIN"}'            # sale "rol":"VENDEDOR"
```
En el navegador: repite el truco de `localStorage` → la vista *Usuarios* abre, pero en *Network* `GET /api/usuarios` responde **403**.

**Rojo → verde:**
```bash
cd backend
./mvnw test -Dtest='ControlAccesoAdminTest,RegistroNoConfiaEnElRolDelClienteTest'   # VERDE
# Quita la defensa: en SecurityConfig cambia .hasAuthority("ROL_ADMIN") por .permitAll()
./mvnw test -Dtest=ControlAccesoAdminTest                                            # ROJO
# Y en AuthServicio: String rol = datos.getOrDefault("rol", "VENDEDOR");
./mvnw test -Dtest=RegistroNoConfiaEnElRolDelClienteTest                             # ROJO
# Restaura con: git checkout -- .
```

---

## 3. Ataque SSRF (≈ 2 min) — rama `main`

```bash
# El backend se consulta a sí mismo y te devuelve el contenido
curl -s -X POST "http://localhost:8080/api/integraciones/consultar-url?url=http://localhost:8080/api/salud"
# Servicio interno de la red de Docker (hostname "adminer", solo resuelve dentro de Docker)
curl -s -X POST "http://localhost:8080/api/integraciones/consultar-url?url=http://adminer:8080/" | head -c 400
# Escáner de puertos
curl -s "http://localhost:8080/api/integraciones/verificar-host?host=mysql&puerto=3306"
```
También desde la pantalla *Reportes → Verificar URL de proveedor*.
Plan B sin internet: no hace falta, todo es interno. Si quieres un recurso propio: `python3 -m http.server 9000` en el host y apunta a `http://host.docker.internal:9000/`.

## 4. Remediación SSRF (≈ 2 min) — rama `endurecimiento-u2`

Muestra el diff: `ValidadorUrlDestino.java` (5 reglas), `IntegracionServicio.java` (línea `// <-- DEFENSA SSRF`).

```bash
curl -i -X POST "http://localhost:8080/api/integraciones/consultar-url?url=http://localhost:8080/api/salud"  # 403 BLOQUEADO
curl -i -X POST "http://localhost:8080/api/integraciones/consultar-url?url=http://adminer:8080/"             # 403
curl -i -X POST "http://localhost:8080/api/integraciones/consultar-url?url=http://2130706433:8080/"          # 403 (127.0.0.1 en decimal)
curl -i -X POST "http://localhost:8080/api/integraciones/consultar-url?url=https://example.com"             # 200 (necesita internet)
```

**Rojo → verde:**
```bash
cd backend
./mvnw test -Dtest='ValidadorUrlDestinoTest,IntegracionServicioSsrfTest'     # VERDE
# Quita la defensa: en IntegracionServicio.consultarUrl cambia
#     destino = validador.validar(url);   por   destino = URI.create(url);
./mvnw test -Dtest=IntegracionServicioSsrfTest                               # ROJO (el secreto interno salió)
```

---

## 5. Plan de Git y Pull Requests

```bash
git checkout -b endurecimiento-u2
# PR 1
git checkout -b fix/bac-control-acceso-servidor endurecimiento-u2
git add backend/src/main/java/com/curso/pv/config/SecurityConfig.java \
        backend/src/main/java/com/curso/pv/auth/AuthServicio.java \
        backend/src/test/java/com/curso/pv/config backend/src/test/java/com/curso/pv/auth adr/001*
git commit -m "fix(bac): exigir sesion y rol ADMIN en el servidor; el registro ya no acepta rol"
# PR 2
git checkout -b fix/ssrf-allowlist endurecimiento-u2
git add backend/src/main/java/com/curso/pv/integracion backend/src/main/resources/application.yml \
        backend/src/test/java/com/curso/pv/integracion adr/002*
git commit -m "fix(ssrf): allowlist, bloqueo de rangos internos y sin redirecciones"
```
Descripción del PR 1: *Problema:* la API era pública y el rol se confiaba al cliente. *Fix:* regla `hasAuthority("ROL_ADMIN")` en rutas sensibles + registro siempre VENDEDOR. *Prueba:* `ControlAccesoAdminTest` y `RegistroNoConfiaEnElRolDelClienteTest` (en rojo al quitar la regla).
Descripción del PR 2: *Problema:* el backend consultaba cualquier URL. *Fix:* `ValidadorUrlDestino` + cliente sin redirecciones. *Prueba:* `ValidadorUrlDestinoTest` e `IntegracionServicioSsrfTest`.

---

## 6. Preguntas probables y cómo contestarlas

**¿Por qué `hasAuthority("ROL_ADMIN")` y no `hasRole("ADMIN")`?** `hasRole` agrega el prefijo `ROLE_`; este proyecto guarda las autoridades como `ROL_ADMIN` (`CodificadorEnClaro.autoridadesDe`). Con `hasRole("ADMIN")` nadie pasaría, ni el admin.

**¿Diferencia entre 401 y 403?** 401 = no sé quién eres (autenticación). 403 = sé quién eres, pero no tienes permiso (autorización).

**¿Por qué no basta con ocultar el menú en React?** Porque el navegador es del usuario: edita `localStorage` o llama la API con `curl`. Lo que el cliente dice no es una garantía.

**¿Por qué corregiste también el registro?** Sin eso, cualquiera crea una cuenta ADMIN y pasa la regla.

**¿Por qué allowlist y no blocklist?** La blocklist se evade (`2130706433`, `0x7f000001`, `127.1`, `[::1]`, un dominio que resuelve a 127.0.0.1). La allowlist niega todo lo que no se aprobó.

**Si hay allowlist, ¿para qué bloquear IPs?** Si un dominio permitido apuntara (o lo hicieran apuntar por DNS) a una IP interna, la allowlist sola lo dejaría pasar.

**¿Por qué no seguir redirecciones?** Un host permitido podría responder `302 → http://169.254.169.254/` y saltarse la validación.

**¿Qué queda sin resolver?** Resto de la API pública (falta *deny by default*), DNS rebinding, HTTP Basic/CSRF/CORS, secretos en claro. Todo está en el reporte como riesgo residual.

### Cambios que te pueden pedir en vivo
- *"Haz que `/api/reportes/resumen` sea solo para ADMIN"* → agrégalo a la lista de `requestMatchers(...)` en `SecurityConfig`.
- *"Que el VENDEDOR también pueda ver reportes"* → `.hasAnyAuthority("ROL_ADMIN", "ROL_VENDEDOR")` en una regla aparte, antes de `/api/**`.
- *"Agrega el proveedor `api.proveedor.com`"* → `hosts-permitidos: "example.com,api.proveedor.com"` en `application.yml`.
- *"Permite el puerto 8443"* → condición del puerto en `ValidadorUrlDestino.validar`.
