<p align="center">
    <img
      src="../media/fhg.gif"
      alt="FoxHole OpenWrt"
      width="180"
      height="180"
    >
</p>

<div align="center">

[![English](https://img.shields.io/badge/%F0%9F%87%AC%F0%9F%87%A7-English-ff7a00?style=flat-square)](../README.md)
[![Русский](https://img.shields.io/badge/%F0%9F%87%B7%F0%9F%87%BA-%D0%A0%D1%83%D1%81%D1%81%D0%BA%D0%B8%D0%B9-ff7a00?style=flat-square)](README.ru.md)
[![Deutsch](https://img.shields.io/badge/%F0%9F%87%A9%F0%9F%87%AA-Deutsch-ff7a00?style=flat-square)](README.de.md)
[![Français](https://img.shields.io/badge/%F0%9F%87%AB%F0%9F%87%B7-Fran%C3%A7ais-ff7a00?style=flat-square)](README.fr.md)
[![Español](https://img.shields.io/badge/%F0%9F%87%AA%F0%9F%87%B8-Espa%C3%B1ol-ff7a00?style=flat-square)](README.es.md)
[![日本語](https://img.shields.io/badge/%F0%9F%87%AF%F0%9F%87%B5-%E6%97%A5%E6%9C%AC%E8%AA%9E-ff7a00?style=flat-square)](README.ja.md)
[![简体中文](https://img.shields.io/badge/%F0%9F%87%A8%F0%9F%87%B3-%E7%AE%80%E4%BD%93%E4%B8%AD%E6%96%87-ff7a00?style=flat-square)](README.zh.md)

</div>

<p align="center">
  <a href="https://github.com/foxhole-team/foxhole-openwrt-client/releases">
    <img src="https://img.shields.io/github/v/release/foxhole-team/foxhole-openwrt-client?label=version&style=flat-square" alt="Version">
  </a>
</p>

# FoxHole OpenWrt

Perfiles VPN, reglas de enrutamiento y un panel sencillo para routers OpenWrt.
Las conexiones VPN salientes utilizan [FoxCore](https://github.com/foxhole-team/foxhole-core).
Las instalaciones compactas usan un módulo cliente independiente para cada
protocolo seleccionado. Un servidor Hysteria opcional acepta conexiones de sus dispositivos.

<p align="center">
  <img src="../media/dashboard.png" width="100%" alt="FoxHole OpenWrt Client dashboard">
</p>

## 🔌 Protocolos VPN compatibles

Módulos VPN de FoxHole disponibles actualmente para el router:

| Protocolo | Opción de instalación |
| --- | --- |
| VLESS | `--vless` |
| Hysteria2 | `--hy2` |
| WireGuard | `--wg` |

## 📋 Requisitos

- OpenWrt 25.12.5 con APK, acceso root y conexión a Internet.
- Paquetes publicados para el firmware, destino, arquitectura y protocolos exactos. La política actual de paquetes y actualizaciones admite `x86/64` y `mediatek/filogic`; compilar un SDK o indicar una arquitectura ARM no valida todos los modelos de router.
- Suficiente flash y RAM para el presupuesto completo y verificado de paquetes. El instalador comprueba dependencias, ABI del kernel y espacio temporal antes de cambiar paquetes.
- Acceso desde una LAN de confianza. Active primero el Wi-Fi si está desactivado en un router nuevo.

En esta beta pública, los módulos VPN de salida utilizan FoxHole Core 1.0.1. La compatibilidad en el código fuente y un binario compilado para otra
arquitectura no bastan para demostrar la compatibilidad con el router. Solo se
pueden instalar paquetes incluidos en un catálogo de publicación autenticado.
El servidor entrante conserva dos hallazgos revisados de dependencias en paquetes
S2/OpenPGP no utilizados; las comprobaciones de la compilación exacta y la caducidad de las excepciones se documentan en [Publicación](RELEASE.md).

## 📦 Instalación

Use una etiqueta de versión publicada y revisada, y el SHA-256 de su archivo
`SHA256SUMS` autenticado por una vía independiente. Este comando verifica el instalador antes de ejecutarlo:

```sh
(set -eu; url='https://github.com/foxhole-team/foxhole-openwrt-client/releases/download/RELEASE_TAG'; f=$(mktemp /tmp/foxhole-install.XXXXXX); trap 'rm -f "$f"' EXIT; uclient-fetch -q -T 60 -O "$f" "$url/install.sh"; printf '%s  %s\n' 'fb0a2bad91a1eebd3591801f79dd6b83fc70bf94ddc1b8d6577f94519de1d1d9' "$f" | sha256sum -c -; sh "$f" --base-url "$url" --manifest-sha256 MANIFEST_SHA256 --apply)
```

Con `--apply`, el instalador interactivo muestra el acuerdo y pregunta `[y/N]`; la opción predeterminada es No. Léalo con `sh install.sh --license`. La instalación no interactiva requiere `--accept-license` después de aceptarlo expresamente. En el asistente del teléfono, la casilla independiente de aceptación empieza desmarcada.

En los catálogos compactos, la opción predeterminada es **solo el cliente
Hysteria2**, almacenado en flash. Con un paquete de versión local verificado, elija un protocolo o combine opciones:

```sh
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --vless --wg --flash --apply
sh install.sh --bundle /tmp/bundle --manifest-sha256 HASH --hy2 --server --ram --apply
```

`-wg` es un alias de `--wg`. Otras opciones reconocidas: `--vmess`, `--tuic`,
`--trojan`, `--shadowsocks`, `--naive`, `--anytls`, `--shadowtls`, `--socks`, `--http`.
Los catálogos compactos combinan módulos publicados con un modo de almacenamiento
común. Cada módulo seleccionado debe estar disponible para su firmware y destino.
`--all` solicita todos los protocolos reconocidos y se rechaza si falta algún
módulo. Los catálogos antiguos schema 1 requieren una única variante exacta.

| Almacenamiento | Comportamiento |
| --- | --- |
| `--flash` | El motor permanece en flash después de reiniciar. Opción predeterminada. |
| `--ram` | El motor usa RAM y descarga su binario fijado después de reiniciar. La configuración permanece en flash. |
| `--auto` | Elige flash si cabe el presupuesto completo; en caso contrario, un conjunto disponible de módulos RAM. |

Quite `--apply` para comprobar el paquete seleccionado sin instalarlo. Nunca se
actualizan los paquetes del kernel para adaptar un paquete incompatible. En los
catálogos compactos, `--server` añade el servidor Hysteria entrante al presupuesto
de recursos. Permanece desactivado hasta que se configura el acceso remoto.

## 🔗 Uso y emparejamiento

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

El acceso remoto requiere el servidor Hysteria seleccionado con `--server`. En un
router con dirección WAN pública, **Crear perfil VPN** añade un cliente remoto.
Al seleccionar un cliente se abre su perfil existente.
El servicio UDP también debe ser accesible desde fuera de la red doméstica.
El cambio automático de VPN en la red doméstica permanece desactivado hasta la
validación real del enrutamiento, incluidas las comprobaciones de bloqueo ante fallos y propiedad del túnel.

En las aplicaciones Android:

El icono Wi-Fi indica solo una conexión Wi-Fi física, sin SSID ni acceso a la ubicación. Buscar y realizar una nueva configuración/vinculación requiere Wi-Fi. La dirección manual se rellena una sola vez con la puerta de enlace IPv4 privada del Wi-Fi actual, si está disponible, y sigue siendo editable.

Gestionar mediante la VPN de casa es una opción independiente, DESACTIVADA por defecto para cada vínculo existente. También exige su confirmación Dirección IP pública (el router tiene una IP pública y un servicio VPN entrante) y una ruta VPN activa utilizable. Esa confirmación no asigna una dirección ni configura el cortafuegos. La aplicación puede intentar gestionar el destino privado guardado a través de esa red VPN con la identidad TLS fijada y la autenticación vinculada existentes; no abre puertos de gestión WAN ni permite nuevas búsquedas/vinculaciones por red móvil.

Solo los perfiles de VPN entrante enviados directamente a la aplicación por un router vinculado y autenticado reciben metadatos separados de enlace con la aplicación. No cambian el URI de conexión, la configuración ni los formatos QR. Las exportaciones genéricas web/QR/de proveedores siguen sin marcar; las indicaciones importadas no establecen confianza por sí solas.

El reconocimiento automático requiere además que coincidan el perfil local guardado, su configuración actual y el vínculo seleccionado, y que ese perfil esté realmente conectado mediante la VPN de la propia aplicación. Se realiza una comprobación limitada por conexión real, sin temporizador, reintentos automáticos ni sondeo de perfiles de proveedores. Repetir vinculación es un proceso explícito con Wi-Fi/permiso/PIN: conserva el registro anterior hasta autenticarse correctamente y nunca acepta silenciosamente una identidad de certificado distinta.

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

Las instalaciones directas por CLI/backend dejan las actualizaciones automáticas desactivadas por defecto. En una configuración nueva desde el teléfono, la casilla visible e independiente empieza activada; desmárquela para rechazarlas. La política se guarda tras la instalación y vinculación. Vincular un router existente conserva su política; puede cambiarla después en Ajustes.

Si está activada, el router comprueba cada día e instala actualizaciones verificadas de paquetes FoxHole. Desvincular el teléfono no desactiva esta política. Los paquetes antiguos sin actualizador necesitan una migración revisada por separado. Consulte [actualizaciones de software](UPDATES.md).

Añada o actualice protocolos mediante **VPN del router → Protocolos** en el router
o teléfono emparejado. El instalador compacto es solo para la configuración inicial.
Conserva copias de recuperación privadas y comprueba que la configuración DHCP
no haya cambiado. Antes de eliminar paquetes mientras el enrutamiento está activo,
siga las instrucciones de [reversión/eliminación](ROLLBACK.md). Use paquetes de
versión verificados. Quedan excluidos los instaladores antiguos y las descargas
exclusivas para ARM; Core sigue admitiendo los perfiles HY2 existentes.

[Comandos](CLI.md) · [Arquitectura](ARCHITECTURE.md) ·
[Compilación y publicación](RELEASE.md) · [Seguridad](../SECURITY.md)

## 💖 Apoyar el desarrollo

Desarrollamos y mantenemos FoxHole OpenWrt íntegramente con nuestro propio tiempo y recursos, con ayuda de herramientas de IA. Su apoyo nos ayuda a dedicar más tiempo al proyecto y acelerar el desarrollo.

[Apoyar el proyecto - monederos de criptomonedas](#cryptocurrency-wallets)

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
