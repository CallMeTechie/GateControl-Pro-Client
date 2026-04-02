# GateControl Pro Client

Windows VPN client with integrated Remote Desktop (RDP) management.

## Features
- WireGuard VPN with auto-connect, kill-switch, split-tunneling
- One-click RDP connections to VMs in the GateControl network
- Slide-out RDP panel with pin support
- E2EE credential handling
- Wake-on-LAN integration
- Session tracking and audit

## Development
```bash
npm install
npm run dev
```

## Build
```bash
npm run build:installer   # NSIS installer
npm run build:portable    # Portable ZIP
```
