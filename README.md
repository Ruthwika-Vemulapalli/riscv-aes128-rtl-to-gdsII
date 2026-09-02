# riscv-aes128-rtl-to-gdsII
# 32-bit RV32I RISC-V Processor with AES-128 Accelerator  
### Complete RTL-to-GDSII ASIC Implementation

![Verilog](https://img.shields.io/badge/HDL-Verilog-blue)
![Cadence](https://img.shields.io/badge/EDA-Cadence-red)
![ASIC](https://img.shields.io/badge/Design-ASIC-green)
![RISC--V](https://img.shields.io/badge/ISA-RV32I-orange)
![AES](https://img.shields.io/badge/Crypto-AES--128-purple)

## 📌 Project Overview

This project presents the implementation of a **32-bit RV32I RISC-V Processor integrated with an AES-128 cryptographic accelerator**, developed through a complete ASIC implementation flow from **RTL design to physical implementation**.

The design integrates a hardware AES-128 engine with a 32-bit RISC-V processor to enable accelerated cryptographic processing. The complete RTL-to-GDSII flow was performed using **Cadence Genus, Innovus, and Tempus**, including synthesis, floorplanning, placement, clock tree synthesis, routing, static timing analysis, physical verification, and timing closure.

The final implementation achieved successful timing closure at **100 MHz**.

---

## 🎯 Key Highlights

- Designed a **32-bit RV32I RISC-V Processor**
- Integrated an **AES-128 cryptographic accelerator**
- Performed complete **RTL-to-GDSII ASIC implementation**
- Executed synthesis using **Cadence Genus**
- Performed floorplanning, placement, CTS and routing using **Cadence Innovus**
- Performed Static Timing Analysis using **Cadence Tempus**
- Achieved timing closure at **100 MHz**
- Achieved:
  - **WNS: +0.268 ns**
  - **TNS: 0**
- Implemented a design containing **29K+ instances**
- Achieved approximately **75.8% core utilization**

---

# 🏗️ System Architecture

The system consists of a 32-bit RV32I processor integrated with a dedicated AES-128 hardware accelerator.

```text
                    ┌──────────────────────┐
                    │                      │
                    │   RV32I RISC-V CPU   │
                    │                      │
                    └──────────┬───────────┘
                               │
                               │
                    ┌──────────▼───────────┐
                    │                      │
                    │  AES-128 Accelerator │
                    │                      │
                    └──────────┬───────────┘
                               │
                               │
                         Encrypted Data
