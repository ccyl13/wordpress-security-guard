# WPSentry

**WordPress Security Auditor** &mdash; Herramienta de analisis de seguridad pasiva para sitios WordPress.

Escanea cualquier instalacion de WordPress en segundos y genera un informe detallado con puntuacion CVSS, referencias OWASP y recomendaciones concretas. Sin instalacion, sin registro, sin intrusiones.

---

## Que analiza

- **Cabeceras HTTP de seguridad** &mdash; CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy y mas
- **Endpoints criticos expuestos** &mdash; xmlrpc.php, wp-login.php, wp-admin, wp-json, readme.html, debug.log...
- **Enumeracion de usuarios** &mdash; detecta si la API REST o los autores exponen nombres de usuario validos
- **Informacion de la instalacion** &mdash; version de WordPress, tema activo, cabecera Generator, WAF detectado
- **Puntuacion de seguridad** &mdash; score 0-100 propio y CVSS 3.1 agregado segun los hallazgos
- **Recomendaciones accionables** &mdash; pasos concretos para corregir cada vulnerabilidad encontrada

## Stack tecnico

- React 18 + TypeScript
- Tailwind CSS
- Vite
- Shadcn/ui
- Lucide icons
- Desplegado en GitHub Pages via GitHub Actions

## Instalacion local

```bash
git clone https://github.com/ccyl13/wordpress-security-guard.git
cd wordpress-security-guard
npm install
npm run dev
```

La aplicacion arranca en `http://localhost:5173`

## Despliegue

El despliegue es automatico via GitHub Actions al hacer push a `main`. El workflow construye el proyecto con Vite y publica el contenido de `/dist` en GitHub Pages.

## Notas de uso

Esta herramienta realiza unicamente analisis pasivo: no explota vulnerabilidades, no modifica datos ni realiza ataques de fuerza bruta. Toda la informacion recopilada es publica o accesible desde el navegador.

**Usar solo en sitios propios o con permiso expreso del propietario.**

## Autor

**Thomas Oneil Alvarez**

- GitHub: [github.com/ccyl13](https://github.com/ccyl13)
- LinkedIn: [linkedin.com/in/thomasoneilalvarez](https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/)

---

*WPSentry &mdash; porque la seguridad no deberia ser opcional.*
