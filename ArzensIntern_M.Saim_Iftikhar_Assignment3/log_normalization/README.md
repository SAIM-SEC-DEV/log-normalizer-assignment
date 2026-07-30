# Security Log Normalizer – AI, Automation & Security Engineering

**Author:** M. Saim Iftikhar  
**Assignment:** Track 09 – Beginner Track (AI, Automation & Security Engineering)  
**Date:** 2026-07-30  

---

## 📌 Overview

This project is a **Python‑based log normalizer** that ingests messy, real‑world security logs from multiple sources (firewall, authentication, DNS, and JSON‑based file access) and transforms them into clean, structured datasets (CSV and JSON). It performs:

- **Timestamp normalisation** – converts all timestamps to **ISO 8601 UTC** (`YYYY‑MM‑DDTHH:MM:SSZ`).
- **Field extraction & validation** – extracts `source_ip`, `event_type`, `user`, `action`, `target`, and `bytes`, validating IP formats and flagging private ranges.
- **Data cleaning** – strips whitespace, handles missing fields, flags malformed lines, and deduplicates near‑identical events.
- **Export** – generates both CSV and JSON output with a consistent schema.

This assignment demonstrates the foundational skills required for security data engineering, SIEM integration, and reproducible analysis pipelines.

---

## 🧰 Requirements

- **Python** ≥ 3.9  
- **No external dependencies** – all logic uses built‑in modules (`csv`, `json`, `re`, `datetime`, `argparse`, `hashlib`, `logging`).  
- If you modify the script to use `dateutil`, install it via:  
  ```bash
  pip install -r requirements.txt