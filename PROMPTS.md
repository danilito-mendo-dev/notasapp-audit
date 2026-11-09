# PROMPTS.md — NotasApp

## Procedencia
| Ítem | Respuesta |
|---|---|
| Herramienta / modelo de IA | Claude (claude.ai), conversación del 7-nov-2026 |
| Prompts hasta app funcional | 3: 1 prompt generó todo el código + 2 prompts de soporte sin cambios de código |
| Prompts totales en la conversación | 6 (1 de generación, 3 de soporte, 1 pregunta, 1 de documentación) |
| Lenguaje y framework | Python 3.14 + Flask (Jinja2) |
| Base de datos | SQLite (módulo sqlite3, sin ORM) |
| Autenticación | Sí: usuario/contraseña, sesión Flask firmada, hash werkzeug |
| Archivo de dependencias | requirements.txt (versiones exactas) |
| ¿Edición manual del código? | No |
| Baseline congelado | tag v0-ai-baseline (commit 6fbe1a5) |
| Cambio del estudiante (no de la IA) | versiones antiguas en requirements.txt para el ejercicio SCA (commit 2a547ff) |

## Prompts de generación (copiados tal cual, en orden)

### Prompt 1 — generación de la app
```text
Soy estudiante y quiero una aplicación web sencilla para practicar. Hazla en Python con Flask y SQLite.

La app es "NotasApp", un gestor de notas personales con estas funciones:

1. Registro e inicio de sesión de usuarios (usuario y contraseña), y cerrar sesión.
2. Cada usuario puede crear, ver, editar y borrar sus notas. Cada nota se ve en la ruta /notes/<id>.
3. Un buscador de notas por título o contenido.
4. Comentarios en las notas. Quiero que los comentarios permitan formato HTML básico, como <b> o <i>, y que se muestren con ese formato.
5. Una página de perfil en /user/<id> que muestre el nombre de usuario y su correo.
6. Un panel /admin que liste todos los usuarios y permita borrar cualquiera.
7. Crea automáticamente un usuario administrador al iniciar la app para poder probarla.

Requisitos técnicos:
- Usa el módulo sqlite3 directamente, sin ORM, porque quiero aprender SQL.
- Pon toda la configuración directamente en app.py para que sea simple, sin variables de entorno ni archivos .env.
- Que se ejecute con "python app.py" en el puerto 5000, accesible desde otras máquinas de mi red, y con el modo de depuración activado para ver los errores mientras desarrollo.
- Usa plantillas HTML con Jinja2 y un poco de CSS para que se vea decente.
- Incluye un requirements.txt con las versiones exactas de cada paquete.
- La base de datos debe crearse sola la primera vez que se ejecuta.

Dame la estructura de carpetas, el código completo de cada archivo y los comandos exactos para instalar y ejecutar la app en Linux usando un entorno virtual (venv).
```

*Resultado:* app completa (app.py, 9 plantillas, style.css, requirements.txt, .gitignore).

### Prompt 2 — soporte (sin cambios de código)
```text
no me deja ejecutar
```
*(captura de la terminal: `python3 app.py` en ~/Descargas → `ModuleNotFoundError: No module named 'nh3'`)*

*Resultado:* la IA explicó que se ejecutaba un app.py suelto fuera de la carpeta del proyecto y sin el venv activado, y dio los comandos de instalación.

### Prompt 3 — soporte (sin cambios de código)
*(solo captura de la terminal, sin texto: `venv/bin/activate` no existía y seguía `No module named 'nh3'`)*

*Resultado:* la IA indicó que faltaba crear el venv (`python3 -m venv venv`) antes de activarlo. Con estos pasos la app arrancó.

### Prompt 4 — soporte (sin cambios de código)
```text
ya hice todo y me sale esto
```
*(captura de la terminal: la app había arrancado; después se ejecutó `rm -rf venv` y volvió el error de `nh3`)*

*Resultado:* la IA explicó que se había borrado el venv por error y dio los comandos para recrearlo.

### Prompt 5 — pregunta (sin cambios de código)
```text
creaste el gitignore_
```

*Resultado:* la IA confirmó el contenido de .gitignore (venv/, __pycache__/, notasapp.db, .secret_key).

### Prompt 6 — documentación
```text
Crea `PROMPTS.md`:
```

*Resultado:* la IA generó un borrador de PROMPTS.md; esta versión es la del estudiante.

## Observación del auditor
El prompt 1 no incluía ningún requisito de seguridad y pedía de forma explícita varios patrones de riesgo (HTML en comentarios, correo en el perfil, admin automático, configuración en código, 0.0.0.0 y modo debug). La IA añadió mitigaciones por su cuenta (sanitización con nh3, correo visible solo para el dueño o el admin, contraseña de admin aleatoria, SECRET_KEY en un archivo aparte) y mantuvo 0.0.0.0 + DEBUG=True porque se pidieron, con un comentario de advertencia.

Además, la IA introdujo cambios no solicitados:
- **Funcionalidad nueva:** notas públicas (casilla `is_public`). Amplía la superficie de ataque: otros usuarios pueden ver y comentar esas notas, y aparecen en la búsqueda.
- **Controles no pedidos:** token CSRF en los formularios POST, consultas parametrizadas, cabeceras CSP / X-Frame-Options / X-Content-Type-Options, cookie SameSite=Lax y respuesta 404 para notas ajenas.

## Prompts de remediación (Parte 6)
Un prompt por hallazgo, un commit por corrección. La IA que corrige es Claude (claude.ai, sesión de auditoría del 9-nov-2026).

### R-01 — F-01: CWE-489 / CWE-605, depurador activo y app en 0.0.0.0
```text
Hallazgo F-01: CWE-489 (código de depuración activo) y CWE-605 en app.py, líneas 33-38.
La app corre con DEBUG = True y HOST = "0.0.0.0", así que el depurador interactivo
de Werkzeug (/console) es accesible desde toda la red local. Corrígelo: desactiva
el modo debug y escucha en 127.0.0.1 por defecto; permite exponerla en la red solo
si se pide de forma explícita. No cambies ningún otro comportamiento. Explica qué
cambiaste y por qué elimina la vulnerabilidad.
```

### R-02 — CWE-1395: dependencias con CVE conocidos (13 CVE en Flask, Jinja2 y Werkzeug)
```text
Hallazgo CWE-1395: pip-audit reporta 13 CVE en Flask 3.0.0, Jinja2 3.1.2 y
Werkzeug 3.0.1 (entre ellos CVE-2024-34069 en el depurador de Werkzeug, con el
EPSS más alto). Actualiza requirements.txt a las versiones mínimas que corrigen
todos los avisos, manteniendo las versiones exactas (==). No cambies el código.
Explica qué cambiaste y cómo comprobarlo con pip-audit.
```

### R-03 — F-04: CWE-532, contraseña del administrador impresa en la terminal
```text
Hallazgo F-04: CWE-532 en app.py, función init_db() (líneas 154-159). La contraseña
aleatoria del administrador se imprime en la terminal, donde queda en el historial
y en capturas de pantalla. Corrígelo para que no se muestre nunca en la salida:
guárdala en un archivo legible solo por el dueño (permisos 600) que git ignore.
No cambies ningún otro comportamiento. Explica qué cambiaste y por qué.
```

### R-04 — F-08: CWE-778, los intentos de login fallidos no se registran
```text
Hallazgo F-08: CWE-778 (registro insuficiente). La app no deja constancia de los
inicios de sesión fallidos ni de otras acciones sensibles: en la terminal solo
aparece "POST /login 200", sin usuario ni resultado. Añade un registro de
seguridad en un archivo (fuera de git) con fecha, IP, evento y usuario para:
login correcto, login fallido, registro, acceso denegado a /admin, token CSRF
inválido y borrado de usuarios por el admin. Evita la inyección en el log
(CWE-117). No cambies ningún otro comportamiento. Explica qué cambiaste y por qué.
```
