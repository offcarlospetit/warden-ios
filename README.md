# Warden iOS SDK (Passkeys)

[![SwiftPM](https://img.shields.io/badge/SwiftPM-compatible-success.svg)](https://github.com/offcarlospetit/warden-ios)
[![Platform](https://img.shields.io/badge/platforms-iOS%2016%2B-blue.svg)](#requisitos)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](#licencia)

SDK nativo en **Swift** para integrar **Passkeys** con tu **Warden API**, replicando la API pública de tu SDK web:

- `WardenClient.shared.configure(_:)`
- `WardenClient.shared.isConfigured`
- `register(email:presentingAnchor:)`
- `login(presentingAnchor:)`

> **Estado:** MVP funcional. Roadmap hacia Android + React Native.

---

## Tabla de contenidos

- [Requisitos](#requisitos)
- [Instalación (Swift Package Manager)](#instalación-swift-package-manager)
- [Configuración de dominio (Associated Domains + AASA)](#configuración-de-dominio-associated-domains--aasa)
- [Uso](#uso)
  - [Configurar el SDK](#configurar-el-sdk)
  - [Registro con Passkey](#registro-con-passkey)
  - [Login con Passkey](#login-con-passkey)
  - [SwiftUI helper (anchor)](#swiftui-helper-anchor)
- [Contratos del backend](#contratos-del-backend)
- [Manejo de errores](#manejo-de-errores)
- [Troubleshooting](#troubleshooting)
- [Versionado](#versionado)
- [Roadmap](#roadmap)
- [Contribuir](#contribuir)
- [Licencia](#licencia)

---

## Requisitos

- **iOS 16.0+**
- **Xcode** con toolchain Swift compatible (este repo usa `swift-tools-version` 6.x)
- **Cuenta de Apple Developer** (para **Associated Domains**)
- **Dominio** con **HTTPS válido** donde sirvas el archivo **AASA** (apple-app-site-association)
- **Warden API** accesible y configurada con tu **`rp.id`** (relying party)

---

## Instalación (Swift Package Manager)

En Xcode:

1. **File → Add Packages…**
2. URL del repo:
