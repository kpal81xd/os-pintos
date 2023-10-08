# PintOS Project

## Prequesites

- QEMU (If using QEMU 5.2+ comment out `--no-kvm` flag)
- Python3
- GCC

## Setup

- Add `pintos` to path with `PATH="/path/to/pintos/src/utils:$PATH"`

## Build

- `make <folder>` with folders `devices`, `filesys`, `threads`, `userprog`, `vm`

## Run 

- `pintos run <program>`

## Test

- `make check` in folders `devices`, `filesys`, `threads`, `userprog`, `vm` 