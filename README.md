# NMIBlocker

This repository contains a **Proof of Concept (POC)** implementation demonstrating how to block Non-Maskable Interrupts (NMI) by patching Windows kernel internals. 

NMIs are critical hardware interrupts that cannot be masked by normal interrupt masking techniques, often used for hardware error reporting. This POC showcases a method to intercept and modify the NMI handler via the Interrupt Descriptor Table (IDT) patching on Intel-based Windows systems.

> **Disclaimer:**  
> This code is for educational and research purposes only. It is an experimental prototype and is not intended for production use. Improper usage may cause system instability or crashes.

## What this project does

- Locates the base address of `ntoskrnl.exe` (Windows kernel image).
- Performs pattern scanning to locate NMI-related functions in the kernel.
- Resolves relative addresses to reach the Interrupt Descriptor Table entries.
- Patches specific IDT entries to disable or redirect NMI handling.

## Usage

This is kernel-mode code intended to be integrated or tested within a Windows kernel driver environment.

## Important Notes

- Tested on Intel CPUs and specific Windows versions — compatibility is not guaranteed.
- Understanding of Windows kernel internals and driver development is required.
- Use at your own risk.

---

Contributions, issues, and suggestions are welcome!
