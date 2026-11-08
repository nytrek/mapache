<p align="center">
  <img src="assets/branding/logo.svg" width="140" alt="Mapache">
</p>
<h1 align="center">Mapache</h1>
<p align="center">Limpia, audita y protege tu Windows</p>
<p align="center"><a href="README.md">English</a></p>

Mapache es una herramienta de terminal para Windows que libera espacio, desinstala programas junto con
sus restos, audita la seguridad del sistema y aplica ajustes de hardening, privacidad y rendimiento que
se pueden deshacer. Está escrita en Python puro, sin dependencias de terceros.

## Funciones

- **Liberar espacio**: cachés, temporales, archivos duplicados, VMs de VirtualBox repetidas y descargas
  grandes, eliminados con la herramienta correcta (VBoxManage, desinstaladores oficiales, DISM).
- **Analizar disco**: qué ocupa espacio: árbol de carpetas, juegos, tipos de archivo y archivos más grandes.
- **Programas**: apps Win32 y de la Store con tamaño medido y último uso (UserAssist y Prefetch),
  desinstalador oficial en silencio cuando se puede y búsqueda de restos (carpetas, claves del registro,
  servicios, tareas, entradas de inicio, accesos directos, reglas de firewall) con respaldo `.reg`.
- **Auditoría de seguridad**: 48 comprobaciones de solo lectura (BitLocker, Secure Boot, Defender, ASR,
  firewall, SMB, LLMNR/NetBIOS, protección de credenciales, artefactos de memoria, persistencia e
  indicios de infostealers) con puntaje y reporte.
- **Hardening**: ajustes de seguridad en tres niveles (básico, avanzado, paranoico), cada uno con su
  riesgo y lo que puede romper.
- **Privacidad**: telemetría de Windows, ID de publicidad, historial de actividad, anuncios del menú
  Inicio, Recall y políticas para Chrome, Edge, Brave y Firefox.
- **Optimización**: programas de inicio (el mismo mecanismo que el Administrador de tareas), tareas
  programadas de terceros y plan de energía. Sin limpiadores de registro, "liberadores de RAM" ni
  desactivar servicios a ciegas.

Hardening, Privacidad y Optimización comparten un motor: antes de aplicar, Mapache crea un punto de
restauración y guarda el valor anterior de cada ajuste, y **Deshacer** los restaura exactamente.

## Seguridad

- `--simulate` muestra lo que haría sin cambiar nada.
- No se borra nada sin selección explícita y una confirmación escrita.
- Las claves del registro y las tareas programadas se exportan antes de eliminarlas.
- Nunca desactiva Microsoft Defender.
- Los datos variables nunca se interpolan en comandos de PowerShell; se pasan por variables de entorno.

Ninguna herramienta de configuración protege de un ataque dirigido por un adversario con muchos recursos.
Mapache apunta a los casos comunes: robo o pérdida del equipo, malware común, ataques en redes
compartidas y datos sensibles que quedan en el disco.

## Uso

Requiere Windows 10 u 11 y Python 3 (probado en 3.14). Algunas funciones necesitan permisos de
administrador; Mapache ofrece reabrirse elevado.

```powershell
python -m mapache                 # menú principal
python -m mapache clean           # liberar espacio
python -m mapache disk            # analizar disco
python -m mapache programs        # desinstalador
python -m mapache audit           # auditoría de seguridad
python -m mapache harden          # hardening
python -m mapache privacy         # privacidad
python -m mapache optimize        # optimización
python -m mapache --simulate      # simulación
python -m mapache --lang en       # interfaz en inglés
```

O doble clic en `Mapache.bat`. La configuración, los registros, los respaldos y los reportes se guardan
en `%APPDATA%\Mapache\`.

## Hoja de ruta

- [x] Limpiador, analizador de disco, desinstalador, auditoría, hardening, privacidad y optimización
- [ ] Escáner más rápido en Rust (lectura directa de la MFT de NTFS)
- [ ] Interfaz gráfica

## Contribuir

[CONTRIBUTING.md](CONTRIBUTING.md) describe la arquitectura y cómo añadir un detector, una comprobación,
un ajuste o un idioma.

## Licencia

[MIT](LICENSE)

## Agradecimientos

Built with the help of Claude Code.
