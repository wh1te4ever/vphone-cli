# AGENTS — vphone-cli

## Project Overview

CLI tool that boots virtual iPhones (PV=3) via Apple's Virtualization.framework, targeting Private Cloud Compute (PCC) research VMs. Used for iOS security research — firmware patching, boot chain modification, and runtime instrumentation.

## Architecture

```
Sources/
├── VPhoneObjC/           # ObjC bridge for private Virtualization.framework APIs
│   ├── include/VPhoneObjC.h
│   └── VPhoneObjC.m
└── vphone-cli/           # Swift executable
    ├── VPhoneCLI.swift          # Entry point, ArgumentParser command
    ├── VPhoneVM.swift           # VM configuration and lifecycle
    ├── VPhoneHardwareModel.swift # PV=3 hardware model creation
    └── VPhoneVMWindow.swift     # AppKit window + touch input translation

Scripts/
├── prepare_firmware.sh               # Downloads IPSWs, merges cloudOS into iPhone
├── prepare_firmware_build_manifest.py # Generates hybrid BuildManifest.plist & Restore.plist
├── patch_firmware.py                 # Patches 6 boot-chain components (41+ modifications)
├── kernel_patcher.py                 # Dynamic kernel patcher (25 patches, string-anchored)
├── build_ramdisk.py                  # Builds SSH ramdisk with trustcache
├── ramdisk_send.sh                   # Sends ramdisk to device via irecovery
├── install_cfw.sh                    # Installs custom firmware to VM disk
├── patch_cfw.py                      # Patches individual CFW binaries
├── create_venv.sh                    # Creates Python venv with native keystone dylib
└── compile_all_libimobiledevice_deps.sh  # Builds libimobiledevice toolchain from source

Root scripts:
├── build_and_sign.sh     # Build Swift binary + sign with private entitlements
├── create_vm.sh          # Create VM directory (disk, SEP storage, ROMs)
├── boot.sh               # Boot VM (headless)
└── boot_dfu.sh           # Boot VM in DFU mode

Research/                 # Research notes and verification reports
researchs/                # Component analysis and architecture docs
```

### Key Patterns

- **Private API access:** All private Virtualization.framework calls go through the ObjC bridge (`VPhoneObjC`). Swift code never calls private APIs directly.
- **Function naming:** ObjC bridge functions use the `VPhone` prefix (e.g., `VPhoneCreateHardwareModel`, `VPhoneConfigureSEP`).
- **Configuration:** CLI options parsed via `ArgumentParser`, converted to `VPhoneVM.Options` struct, then used to build `VZVirtualMachineConfiguration`.
- **Error handling:** `VPhoneError` enum with `CustomStringConvertible` for user-facing messages.
- **Window management:** `VPhoneWindowController` wraps `NSWindow` + `VZVirtualMachineView`. Touch input translated from mouse events to multi-touch via `VPhoneVMView`.

---

## Firmware Assembly Pipeline

The firmware is a **PCC/iPhone hybrid** — PCC boot infrastructure wrapping iPhone iOS userland.

### Pipeline Stages

```
1. prepare_firmware.sh      Download iPhone + cloudOS IPSWs, merge, generate hybrid plists
        ↓
2. patch_firmware.py        Patch 6 boot-chain components for signature bypass + debug
        ↓
3. build_ramdisk.py         Build SSH ramdisk from SHSH blob, inject tools, sign with IM4M
        ↓
4. create_vm.sh             Create VM directory (sparse disk, SEP storage, copy ROMs)
        ↓
5. boot_dfu.sh              Boot VM in DFU mode
        ↓
6. ramdisk_send.sh          Load boot chain + ramdisk via irecovery
        ↓
7. install_cfw.sh           Mount Cryptex, patch userland, install jailbreak tools
```

### Component Origins

The firmware merges two Apple IPSWs:
- **iPhone IPSW:** `iPhone17,3_26.1_23B85_Restore.ipsw` (d47ap)
- **cloudOS IPSW:** PCC vresearch101ap IPSW (CDN hash URL)

`prepare_firmware.sh` extracts both, then copies cloudOS boot chain into the
iPhone restore directory (`kernelcache.*`, `Firmware/{agx,all_flash,ane,dfu,pmp}/*`,
`Firmware/*.im4p`). The cloudOS extract is deleted after merge.

#### Boot Chain — from PCC (cloudOS / vresearch101ap)

| Component | File | Patched | Patch Purpose |
|-----------|------|---------|---------------|
| AVPBooter | `AVPBooter.vresearch1.bin` | Yes (1) | DGST signature validation bypass |
| LLB | `Firmware/all_flash/LLB.vresearch101.RELEASE.im4p` | Yes (6) | Serial + image4 bypass + boot-args + rootfs + panic |
| iBSS | `Firmware/dfu/iBSS.vresearch101.RELEASE.im4p` | Yes (2) | Serial labels + image4 callback bypass |
| iBEC | `Firmware/dfu/iBEC.vresearch101.RELEASE.im4p` | Yes (3) | Serial + image4 bypass + boot-args |
| SPTM | `Firmware/all_flash/sptm.vresearch1.release.im4p` | No | — |
| TXM | `Firmware/txm.iphoneos.research.im4p` | Yes (1) | Trustcache validation bypass |
| SEP Firmware | `Firmware/all_flash/sep-firmware.vresearch101.RELEASE.im4p` | No | — |
| DeviceTree | `Firmware/all_flash/DeviceTree.vphone600ap.im4p` | No | — |
| KernelCache | `kernelcache.release.vphone600` | Yes (25) | APFS, MAC, debugger, launch constraints, etc. |
| GPU/ANE/PMP | `Firmware/{agx,ane,pmp}/*` | No | — |

> TXM filename says "iphoneos" but is copied from cloudOS IPSW (`prepare_firmware.sh` line 81).

#### OS / Filesystem — from iPhone (iPhone17,3)

| Component | Notes |
|-----------|-------|
| Cryptex1,SystemOS | System volume DMG |
| Cryptex1,AppOS | App volume DMG |
| OS | iPhone OS image |
| SystemVolume | System partition |
| StaticTrustCache | Static trust cache |
| AppleLogo / RestoreLogo | Boot logos |
| RecoveryMode | Recovery mode resources |
| Cryptex1 metadata/keys | Merged from iPhone erase identity into PCC identities |

#### Ramdisk — source depends on build identity

| Identity | Ramdisk Source |
|----------|---------------|
| Erase (Identity 0) | PCC cloudOS (PROD erase ramdisk) |
| Upgrade (Identity 1) | iPhone (upgrade ramdisk) |
| Research Erase (Identity 2) | PCC cloudOS (erase ramdisk) |
| Research Upgrade (Identity 3) | iPhone (upgrade ramdisk) |
| Recovery (Identity 4) | None |

### Build Identities

`prepare_firmware_build_manifest.py` generates 5 identities in BuildManifest.plist:

| # | Name | Boot Chain | Ramdisk | Cryptex1 | Variant |
|---|------|-----------|---------|----------|---------|
| 0 | Erase | PCC RELEASE | PCC erase | iPhone | `Darwin Cloud Customer Erase Install (IPSW)` |
| 1 | Upgrade | PCC RESEARCH | iPhone upgrade | iPhone | `Darwin Cloud Customer Upgrade Install (IPSW)` |
| 2 | Research Erase | PCC RESEARCH | PCC erase | None | `Darwin Cloud Customer Research Erase Install (IPSW)` |
| 3 | Research Upgrade | PCC RESEARCH | iPhone upgrade | None | `Darwin Cloud Customer Research Upgrade Install (IPSW)` |
| 4 | Recovery | PCC RESEARCH | None | None | `Darwin Cloud Customer Recovery (IPSW)` |

idevicerestore selects Identity 0 by partial-matching `Info.Variant` against
`"Erase Install (IPSW)"` while excluding `"Research"`.

### Patched Components Summary

**Boot chain patches** (`patch_firmware.py`) — all 6 targets from **PCC**:

| Component | Patches | Technique |
|-----------|---------|-----------|
| AVPBooter | 1 | `mov x0, #0` (DGST bypass) |
| iBSS | 2 | Serial labels + image4 callback NOP |
| iBEC | 3 | Serial + image4 NOP + boot-args string replace |
| LLB | 6 | Serial + image4 + boot-args + rootfs + panic (fixed offsets) |
| TXM | 1 | `mov x0, #0` at fixed offset 0x2C1F8 |
| KernelCache | 25 | Dynamic via `KernelPatcher` (string anchors, ADRP+ADD xrefs, BL frequency) |

**CFW patches** (`patch_cfw.py` / `install_cfw.sh`) — all 4 targets from **iPhone** Cryptex SystemOS:

| Binary | Technique | Purpose |
|--------|-----------|---------|
| seputil | String patch (`/%s.gl` → `/AA.gl`) | Gigalocker UUID fix |
| launchd_cache_loader | NOP (disassembly-anchored) | Bypass cache validation |
| mobileactivationd | Return true (disassembly-anchored) | Skip activation check |
| launchd.plist | Plist injection | Add bash/dropbear/trollvnc daemons |

### Boot Flow

```
AVPBooter (ROM, PCC)
  → LLB (PCC, patched)
    → iBSS (PCC, patched, DFU)
      → iBEC (PCC, patched, DFU)
        → SPTM + TXM (PCC, TXM patched)
          → KernelCache (PCC, 25 patches)
            → Ramdisk (PCC or iPhone, SSH-injected)
              → iOS userland (iPhone, CFW-patched)
```

### Ramdisk Build (`build_ramdisk.py`)

1. Extract IM4M from SHSH blob
2. Process 8 components: iBSS, iBEC, SPTM, DeviceTree, SEP, TXM, KernelCache, Ramdisk+Trustcache
3. For ramdisk: extract base DMG → create 254 MB APFS volume → mount → inject SSH tools from `ramdisk_input.tar.zst` → re-sign Mach-Os with ldid + signcert.p12 → build trustcache
4. Sign all components with IM4M manifest → output to `Ramdisk/` directory as IMG4 files

### CFW Installation (`install_cfw.sh`)

7 phases, safe to re-run (idempotent):
1. Decrypt/mount Cryptex SystemOS and AppOS DMGs (`ipsw` + `aea`)
2. Patch seputil (gigalocker UUID)
3. Install GPU driver (AppleParavirtGPUMetalIOGPUFamily)
4. Install iosbinpack64 (jailbreak tools)
5. Patch launchd_cache_loader (NOP cache validation)
6. Patch mobileactivationd (activation bypass)
7. Install LaunchDaemons (bash, dropbear SSH, trollvnc)

---

## Coding Conventions

### Swift

- **Style:** Pragmatic, minimal. No unnecessary abstractions.
- **Sections:** Use `// MARK: -` to organize code within files.
- **Access control:** Default (internal). Only mark `private` when needed for clarity.
- **Async:** Use `async/await` for VM lifecycle. `@MainActor` for UI and VM start operations.
- **Naming:** Types are `VPhone`-prefixed (`VPhoneVM`, `VPhoneWindowController`). Match Apple framework conventions.

### ObjC Bridge

- All functions are C-style (no ObjC classes exposed to Swift).
- Return `nil`/`NULL` on failure — caller handles gracefully.
- Header documents the private API being wrapped in each function's doc comment.

### Shell Scripts

- Use `zsh` with `set -euo pipefail`.
- Scripts resolve their own directory via `${0:a:h}` or `$(cd "$(dirname "$0")" && pwd)`.
- Build script (`build_and_sign.sh`) handles both compilation and entitlement signing.

### Python Scripts

- Firmware patching uses `capstone` (disassembly), `keystone-engine` (assembly), and `pyimg4` (IM4P handling).
- `kernel_patcher.py` uses dynamic pattern finding (string anchors, ADRP+ADD xrefs, BL frequency analysis) — nothing is hardcoded to specific offsets.
- Each patch is logged with offset and before/after state.
- Scripts operate on a VM directory and auto-discover the `*Restore*` subdirectory.
- **Environment:** Use the project venv (`source .venv/bin/activate`). Create with `zsh Scripts/create_venv.sh`. All deps in `requirements.txt`: `capstone`, `keystone-engine`, `pyimg4`.

## Build & Sign

The binary requires private entitlements to use PV=3 virtualization:

- `com.apple.private.virtualization`
- `com.apple.private.virtualization.security-research`
- `com.apple.security.virtualization`
- `com.apple.vm.networking`
- `com.apple.security.get-task-allow`

Always use `build_and_sign.sh` — never `swift build` alone, as the unsigned binary will fail at runtime.

## VM Creation (`create_vm.sh`)

Creates a VM directory with:
- Sparse disk image (default 64 GB)
- SEP storage (512 KB flat file)
- AVPBooter + AVPSEPBooter ROMs (copied from `/System/Library/Frameworks/Virtualization.framework/`)
- NVRAM and machineIdentifier auto-created on first boot

CLI flags: `--dir`, `--disk-size`, `--rom`, `--seprom`.

## Design System

### Intent

**Who:** Security researchers working with Apple firmware and virtual devices. Technical, patient, comfortable in terminals. Likely running alongside GDB, serial consoles, and SSH sessions.

**Task:** Boot, configure, and interact with virtual iPhones for firmware research. Monitor boot state, capture serial output, debug at the firmware level.

**Feel:** Like a research instrument. Precise, informative, honest about internal state. No decoration — every pixel earns its place.

### Palette

- **Background:** Dark neutral (`#1a1a1a` — near-black, low blue to reduce eye strain during long sessions)
- **Surface:** `#242424` (elevated panels), `#2e2e2e` (interactive elements)
- **Text primary:** `#e0e0e0` (high contrast without being pure white)
- **Text secondary:** `#888888` (labels, metadata)
- **Accent — status green:** `#4ade80` (VM running, boot success)
- **Accent — amber:** `#fbbf24` (DFU mode, warnings, in-progress states)
- **Accent — red:** `#f87171` (errors, VM stopped with error)
- **Accent — blue:** `#60a5fa` (informational, links, interactive highlights)

Rationale: Dark surfaces match the terminal-adjacent workflow. Status colors borrow from oscilloscope/JTAG tooling — green for good, amber for attention, red for fault. No brand colors — this is a tool, not a product.

### Typography

- **UI font:** System monospace (SF Mono / Menlo). Everything in this tool is technical — monospace respects the content.
- **Headings:** System sans (SF Pro) semibold, used sparingly for section labels only.
- **Serial/log output:** Monospace, `#e0e0e0` on dark background. No syntax highlighting — raw output, exactly as received.

### Depth

- **Approach:** Flat with subtle 1px borders (`#333333`). No shadows, no blur. Depth through color difference only.
- **Rationale:** Shadows suggest consumer software. Borders suggest instrument panels. This is an instrument.

### Spacing

- **Base unit:** 8px
- **Component padding:** 12px (1.5 units)
- **Section gaps:** 16px (2 units)
- **Window margins:** 16px

### Components

- **Status indicator:** Small circle (8px) with color fill + label. No animation — state changes are instantaneous.
- **VM display:** Full-bleed within its container. No rounded corners on the display itself.
- **Log output:** Scrolling monospace region, bottom-anchored (newest at bottom). No line numbers unless requested.
- **Toolbar (if present):** Icon-only, 32px touch targets, subtle hover state (`#2e2e2e` -> `#3a3a3a`).
