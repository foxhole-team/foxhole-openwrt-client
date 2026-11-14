<h1 align="center">FoxHole OpenWrt</h1>

<div align="center">

Perfiles VPN, reglas de enrutamiento y un panel sencillo para routers OpenWrt.
Las conexiones VPN salientes utilizan [FoxHole Core](https://github.com/foxhole-team/foxhole-core).
Las instalaciones compactas usan un módulo cliente por protocolo seleccionado. La versión 1.0.8 añade un paquete opcional y verificado por separado para el servidor Hysteria2 entrante. El acceso remoto requiere una dirección WAN pública y estática y un puerto UDP accesible desde el exterior.

</div>

<p align="center">
    <img
      src="../media/fhg.gif"
      alt="FoxHole OpenWrt"
      width="180"
      height="180"
    >
</p>

<div align="center">

[🇬🇧 English](../README.md) · [🇷🇺 Русский](README.ru.md) · [🇩🇪 Deutsch](README.de.md) · [🇫🇷 Français](README.fr.md) · [🇪🇸 **Español**](README.es.md) · [🇯🇵 日本語](README.ja.md) · [🇨🇳 简体中文](README.zh.md) · [🇸🇦 العربية](README.ar.md)

</div>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client/releases">
    <img src="https://img.shields.io/github/v/release/foxhole-team/foxhole-openwrt-client?label=version&style=flat-square" alt="Version">
  </a>
  <img src="https://img.shields.io/badge/status-beta-yellow?style=flat-square" alt="Status: beta">
</p>

<a id="ecosystem"></a>
<a id="-ecosistema-foxhole"></a>

<div align="center">
  <strong>FoxHole ecosystem</strong><br>
  <a href="https://github.com/foxhole-team/foxhole-guard">FoxHole Guard</a> ·
  <a href="https://github.com/foxhole-team/foxhole-vpn">FoxHole VPN</a> ·
  <a href="https://github.com/foxhole-team/foxhole-core">FoxHole Core</a> ·
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client"><strong>FoxHole OpenWRT</strong></a> ·
  <a href="https://github.com/foxhole-team/foxhole-db">FoxHole DB</a>

<details>
<summary>Funciones de los proyectos</summary>

| Proyecto | Función |
| --- | --- |
| [FoxHole Guard](https://github.com/foxhole-team/foxhole-guard) | Android: VPN, Tor/I2P, reglas de tráfico y supervisión local |
| [FoxHole VPN](https://github.com/foxhole-team/foxhole-vpn) | Android: cliente VPN sencillo y gestión de OpenWrt emparejado |
| [FoxHole Core](https://github.com/foxhole-team/foxhole-core) | Núcleo de red común en Rust; funciones según compilación |
| [**FoxHole OpenWrt**](https://github.com/foxhole-team/foxhole-openwrt-client) | VPN del router y gestión de la red local |
| [FoxHole DB](https://github.com/foxhole-team/foxhole-db) | Reglas firmadas y datos de referencia |

</details>

</div>

<p align="center"><a href="#quickstart">Empezar</a> · <a href="#features">Funciones</a> · <a href="#details">Detalles</a> · <a href="#whats-new">Novedades</a></p>

<a id="whats-new"></a>

> **🆕 Novedades - 1.0.8 Beta**
>
> - Añadida compatibilidad con OpenWrt 25.12.6
> - Optimización de la interfaz
> - Añadido un paquete Hysteria2 opcional y verificado por separado (requiere una IP pública estática)
> - Actualizadas la ayuda, la comprobación de actualizaciones y la sección Acerca de
> - Diario solo en FLASH, con retención circular de hasta 30 días y uso de almacenamiento limitado
> - Mejoradas la administración del router mediante VPN y la reinstalación del paquete en RAM
>
> Aplicaciones asociadas: FoxHole VPN 1.0.6 y Guard 1.0.7 corrigen la instalación y configuración iniciales del router. Guard también actualiza los transportes Tor Lyrebird y conjure-client
>
> La activación permanente del bootstrap sigue deshabilitada. La recuperación tras un arranque en frío no está validada; sigue pendiente el problema de comprobación de la ruta de las bibliotecas ELF

<a id="features"></a>

## 🔌 Protocolos VPN compatibles

Módulos VPN de FoxHole disponibles actualmente para el router:

| Protocolo | Opción de instalación | Descripción |
| --- | --- | --- |
| VLESS | `--vless` | Conexión proxy a un servidor VLESS compatible con los parámetros definidos en el perfil VPN. |
| Hysteria2 | `--hy2` | Conexión a un servidor Hysteria2 mediante QUIC/UDP, proporcionada por su módulo cliente independiente. |
| WireGuard | `--wg` | Túnel IP de capa 3 hacia un par WireGuard; el perfil define claves, direcciones y parámetros de red. |

## 📋 Requisitos

- OpenWrt 25.12.5 o 25.12.6 con el gestor de paquetes apk y acceso root. Las descargas directas necesitan Internet en el router; un `--bundle` local solo requiere una LAN de confianza.
- Paquetes publicados para el firmware, destino, arquitectura y protocolos exactos. La política actual de paquetes y actualizaciones admite `x86/64` y `mediatek/filogic`; compilar un SDK o indicar una arquitectura ARM no valida todos los modelos de router.
- Suficiente flash y RAM para el presupuesto completo y verificado de paquetes. El instalador comprueba dependencias, ABI del kernel y espacio temporal antes de cambiar paquetes.
- Acceso desde una red local de confianza. Para detectar y configurar inicialmente desde Android, conecte el teléfono al Wi-Fi del router.

La [versión v1.0.6](https://github.com/foxhole-team/foxhole-openwrt-client/releases/tag/v1.0.6) incluye BASE 1.0.6-r1 y módulos cliente de FoxHole Core 1.0.4. Las actualizaciones Core compatibles pueden instalarse por separado. La disponibilidad y compatibilidad dependen de la versión, el firmware y el target.

La compatibilidad en el código fuente y un binario compilado para otra
arquitectura no bastan para demostrar la compatibilidad con el router. Solo se
pueden instalar paquetes incluidos en un catálogo de publicación autenticado.
El servidor entrante conserva dos hallazgos revisados de dependencias en paquetes
S2/OpenPGP no utilizados; las comprobaciones de la compilación exacta y la caducidad de las excepciones se documentan en [Publicación](RELEASE.md).

<a id="quickstart"></a>

## 📦 Instalación

Este cliente conecta con su propio servidor o proveedor VPN. No incluye servidores VPN preparados ni acceso a ellos.

Elija una versión publicada y verificada. Sustituya `RELEASE_TAG` por su etiqueta, `MANIFEST_SHA256` por el SHA-256 de confianza de su `SHA256SUMS` e `INSTALLER_SHA256` por el SHA-256 de su `install.sh`. Autentique estos valores por una vía independiente. El instalador se verifica antes de ejecutarse:

```sh
(
  set -eu
  release_tag='RELEASE_TAG'
  manifest_sha256='MANIFEST_SHA256'
  installer_sha256='INSTALLER_SHA256'
  url="https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/$release_tag"
  installer=$(mktemp /tmp/foxhole-install.XXXXXX)
  trap 'rm -f "$installer"' EXIT
  uclient-fetch -q -T 60 -O "$installer" "$url/install.sh"
  printf '%s  %s\n' "$installer_sha256" "$installer" | sha256sum -c -
  sh "$installer" --base-url "$url" --manifest-sha256 "$manifest_sha256" --apply
)
```

Con `--apply`, el instalador interactivo muestra el acuerdo y pregunta `[y/N]`; la opción predeterminada es No. Léalo con `sh install.sh --license`. La instalación no interactiva requiere `--accept-license` después de aceptarlo expresamente. En el asistente del teléfono, la casilla independiente de aceptación empieza desmarcada.

En los catálogos compactos, la opción predeterminada es **solo el cliente
Hysteria2**, almacenado en flash. Con un paquete de versión local verificado, elija un protocolo o combine opciones:

```sh
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --vless --wg --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --ram --apply
```

`-wg` es un alias de `--wg`. Otras opciones reconocidas: `--vmess`, `--tuic`,
`--trojan`, `--shadowsocks`, `--naive`, `--anytls`, `--shadowtls`, `--socks`, `--http`.
Cada módulo debe estar publicado para el firmware y destino. En un catálogo compacto, `--all` selecciona todos los protocolos de cliente publicados para la plataforma. Los módulos seleccionados deben admitir un modo de almacenamiento común. Un protocolo solicitado explícitamente se rechaza si falta su módulo. Los catálogos antiguos schema 1 requieren una variante exacta; allí `--all` significa todos los protocolos reconocidos.

| Almacenamiento | Comportamiento |
| --- | --- |
| `--flash` | El motor permanece en flash después de reiniciar. Opción predeterminada. |
| `--ram` | El binario del motor se carga en RAM y se obtiene de nuevo cuando hace falta tras reiniciar. La configuración permanece en flash. |
| `--auto` | Elige flash si cabe el presupuesto completo; en caso contrario, un conjunto disponible de módulos RAM. |

El modo de almacenamiento `--ram` es distinto del bootstrap RAM nativo experimental. La inscripción persistente sigue desactivada, la recuperación tras un arranque en frío no está validada y la admisión de la ruta ELF personalizada sigue sin resolverse. Consulte las [limitaciones del bootstrap RAM](RAM-BOOTSTRAP.md).

Quite `--apply` para comprobar el paquete sin instalarlo. Nunca se actualizan paquetes del kernel para adaptar un paquete incompatible. En catálogos compactos, `--server` solo está disponible si el catálogo elegido contiene un paquete compatible y verificado para el servidor Hysteria entrante; solo entonces se añade al presupuesto de recursos. Permanece desactivado hasta configurar el acceso remoto.

<p align="center">
  <img src="../media/dashboard.png" width="100%" alt="FoxHole OpenWrt Client dashboard">
</p>

<a id="details"></a>

## 🔗 Uso y emparejamiento

Cambiar el PIN restablece los emparejamientos: habrá que volver a conectar el teléfono, mientras se conservan los perfiles VPN y los ajustes.

Abra **LuCI → Services → FoxHole**, elija un PIN y añada un perfil VPN. Las reglas
pueden enviar el tráfico de dispositivos, dominios y países por VPN o directamente.

`ACCESS_LOCAL_NETWORK` - buscar, configurar y gestionar routers. En Android 17 (API 37) o posterior, si la aplicación tiene como objetivo API 37 o posterior, solicita el permiso del sistema antes de las acciones LAN. Denegarlo bloquea esas acciones.

La configuración desde el teléfono busca el router en la puerta de enlace IPv4
privada del Wi-Fi conectado; también permite introducir una dirección manualmente.
Antes del emparejamiento,
el teléfono verifica la identidad SSH y la identidad TLS privada del router en la LAN.
Se conserva cualquier PIN existente. El destino de gestión sigue siendo privado.
Desemparejar elimina el acceso de administración. Elimine el cliente remoto por
separado para revocar sus credenciales VPN. Eliminar un perfil compartido antiguo
solo borra su registro; no puede revocar las credenciales de un proveedor VPN externo.

Crear clientes VPN remotos requiere un paquete de servidor Hysteria entrante verificado por separado, instalable con `--server` solo si está en el catálogo de la versión elegida. También hacen falta una dirección WAN pública y un puerto UDP accesible desde el exterior. **Crear perfil VPN** añade entonces un cliente remoto; seleccionar uno existente abre su perfil.

El cambio automático de VPN en la red doméstica permanece desactivado hasta la
validación real del enrutamiento, incluidas las comprobaciones de bloqueo ante fallos y propiedad del túnel.

En las aplicaciones Android:

El icono Wi-Fi indica solo una conexión Wi-Fi física, sin SSID ni acceso a la ubicación. Buscar y realizar una nueva configuración/vinculación requiere Wi-Fi. La dirección manual se rellena una sola vez con la puerta de enlace IPv4 privada del Wi-Fi actual, si está disponible, y sigue siendo editable.

Gestionar mediante la VPN de casa es una opción independiente, DESACTIVADA por defecto para cada vínculo existente. También exige su confirmación Dirección IP pública (el router tiene una IP pública y un servicio VPN entrante) y una ruta VPN activa utilizable. Esa confirmación no asigna una dirección ni configura el cortafuegos. La aplicación puede intentar gestionar el destino privado guardado a través de esa red VPN con la identidad TLS fijada y la autenticación vinculada existentes; no abre puertos de gestión WAN ni permite nuevas búsquedas/vinculaciones por red móvil.

Solo los perfiles de VPN entrante enviados directamente a la aplicación por un router vinculado y autenticado reciben metadatos separados de enlace con la aplicación. No cambian el URI de conexión, la configuración ni los formatos QR. Las exportaciones genéricas web/QR/de proveedores siguen sin marcar; las indicaciones importadas no establecen confianza por sí solas.

El reconocimiento automático requiere además que coincidan el perfil local guardado, su configuración actual y el vínculo seleccionado, y que ese perfil esté realmente conectado mediante la VPN de la propia aplicación. Se realiza una comprobación limitada por conexión real, sin temporizador, reintentos automáticos ni sondeo de perfiles de proveedores. Repetir vinculación es un proceso explícito con Wi-Fi/permiso/PIN: conserva el registro anterior hasta autenticarse correctamente y nunca acepta silenciosamente una identidad de certificado distinta.

## Limitaciones

- Las reglas por país usan rangos IP y las reglas de dominio dependen del DNS del router. No determinan el país del propietario del sitio ni analizan contenido HTTPS.
- La pérdida inesperada de la conexión Core activa bloquea su enrutamiento VPN. La opción Kill switch independiente controla el bloqueo sin perfil activo y está desactivada por defecto.
- Las prioridades, excepciones locales y límites del servidor entrante se describen en la [arquitectura](ARCHITECTURE.md).

## 🧩 Añadir un protocolo más adelante

En **VPN del router → Protocolos**, seleccione un protocolo disponible y confirme
su instalación. Los mismos controles están disponibles en la aplicación Android
emparejada. Cada protocolo utiliza un paquete de motor compacto y firmado por
separado; no se sustituye silenciosamente por un motor universal más grande.

Añadir un protocolo no utilizado mantiene la VPN actual en funcionamiento.
Actualizar el protocolo activo solicita una reconexión. Deje de usar un protocolo
antes de eliminarlo. Solo se ofrecen paquetes publicados para el destino exacto de su router.

## ♻️ Actualización y eliminación

### 📥 Actualizaciones de paquetes FoxHole

En **Ajustes → Actualización de FoxHole** de la interfaz web o aplicación vinculada, la comprobación e instalación usan la misma transacción autenticada. Se actualizan el panel/runtime de FoxHole y los módulos de protocolos cliente instalados y seleccionados, conservando su modo FLASH/RAM. Los protocolos nuevos se instalan por separado. Se conservan perfiles y vínculo; no se actualizan el firmware de OpenWrt ni otros paquetes del sistema.

Las instalaciones directas CLI/backend dejan las actualizaciones automáticas desactivadas por defecto. En una configuración inicial web o Android, una casilla separada y visible comienza activada; desmárquela para rechazarlas. Las políticas existentes del router, incluido un rechazo, se conservan al vincular y abrir la configuración. Puede cambiarlas más tarde en Ajustes.

Si está activada, el router comprueba cada día e instala actualizaciones verificadas de paquetes FoxHole. Desvincular el teléfono no desactiva esta política. Los paquetes antiguos sin actualizador necesitan una migración revisada por separado. Consulte [actualizaciones de software](UPDATES.md).

Añada o actualice protocolos mediante **VPN del router → Protocolos** en el router
o teléfono emparejado. El instalador compacto es solo para la configuración inicial.
Conserva copias de recuperación privadas y comprueba que la configuración DHCP
no haya cambiado. Antes de eliminar paquetes mientras el enrutamiento está activo,
siga las instrucciones de [reversión/eliminación](ROLLBACK.md). Use paquetes de
versión verificados. No se utilizan instaladores antiguos ni descargas exclusivas para ARM. FoxHole Core admite Hysteria2. Los perfiles legacy siguen usando el motor Hysteria separado y no migran automáticamente a Core. Detenga manualmente una conexión Hysteria legacy activa antes de actualizar.

- **Instrucciones:** [CLI](CLI.md) · [Updates](UPDATES.md) · [Rollback](ROLLBACK.md)
- **Arquitectura:** [Architecture](ARCHITECTURE.md) · [Mobile networks](MOBILE-NETWORKS.md) · [Backup](BACKUP-ARCHITECTURE.md) · [Profile origin](PROFILE-ORIGIN.md)
- **Mantenimiento:** [Release](RELEASE.md) · [Bundle transport](BUNDLE-TRANSPORT.md) · [RAM install](RAM-INSTALL.md) · [Bootstrap](RAM-BOOTSTRAP.md) · [Prerequisites](RAM-PREREQUISITES.md) · [RAM updates](RAM-UPDATE-CONTROLLER.md) · [Engine origin](engine-release-origin.md) · [Security](../SECURITY.md)

## 🤝 Contribuir

Informe de errores y proponga cambios mediante [Issues](https://github.com/foxhole-team/foxhole-openwrt-client/issues).

## 💖 Apoyar el desarrollo

Desarrollamos y mantenemos FoxHole OpenWrt íntegramente con nuestro propio tiempo y recursos, utilizando herramientas de IA en el desarrollo. Su apoyo nos ayuda a dedicar más tiempo al proyecto y acelerar el desarrollo.

<a id="cryptocurrency-wallets"></a>

### 🪙 Monederos de criptomonedas

**XMR (Monero):**

```text
48yBVPTdcyJ1WoJtnKmVpEZziEsDy4HvbCW7eQDS9mfdiWPFXwZ8F5h9YZ2UTTBLxPcJgQgvth7iqLZM2yMCaQ432qaouqr
```

**BTC (Bitcoin):**

```text
bc1qatnyy7jcpqrp0d3dk9rta9vqfejgh4mysd6m2f
```

**ETH (Ethereum):**

```text
0xDEBA357Cc8f5E865ea7FFa98E138C8241A16A465
```

## 📄 Licencias

[Licencia](../LICENSE) · [Licencias de terceros](../THIRD_PARTY_NOTICES.md)
