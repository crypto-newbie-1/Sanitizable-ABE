# Sanitizable-ABE

This repository contains the source code and Docker environment for the paper: **"Sanitizable and Revocable Outsourced CP-ABE Against Internal Threats in Vehicular Networks"**.

## 📖 Overview

Ciphertext-Policy Attribute-Based Encryption (CP-ABE) is a cryptographic primitive for secure and fine-grained data sharing in the Internet of Vehicles (IoV). Traditional schemes often rely on the ideal assumption that data owners are fully honest. However, potentially malicious data owners may sell their encryption randomness to unauthorized users for financial gain, leading to severe privacy leaks.

To mitigate this threat, we propose an efficient, sanitizable, and revocable outsourced access control scheme. 

### ✨ Key Features
* **Internal Threat Defense:** Mitigates the risk of malicious data owners bypassing access control.
* **High Efficiency:** Constructed over Type-III pairings, supporting arbitrary attributes without linear parameter expansion. Accelerates encryption (~3x), sanitization (~1.7x), and total decryption (~9x) compared to recent baselines.
* **Storage Optimization:** Reduces the storage of public parameters and secret keys significantly (over 12x and 2x respectively).
* **Provable Security:** Achieves Adaptive-CPA security, making it highly practical for resource-constrained terminals in IoV.

---

## 🐳 Docker Quickstart (Recommended)

To ensure a seamless experience without worrying about complex cryptographic library dependencies, we provide a pre-built Docker image with the complete running environment.

**1. Pull the Docker Image**
```bash
docker pull zhiyixu/sanitizable-abe:v2
