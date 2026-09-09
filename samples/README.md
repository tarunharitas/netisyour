# Sample PCAP guidance

This folder is meant to hold **your own, sanitized** PCAP files for offline testing with:

```bash
sentinel-nids --config config.yaml analyze --pcap samples/your_file.pcap
```

## Getting a safe sample capture

- Capture a short session (a minute or two) of your own device browsing a couple of ordinary sites.
- Use Wireshark or `tcpdump`/`dumpcap` on a network you own or are explicitly authorized to inspect.
- Review the capture and remove/redact anything sensitive (credentials, personal browsing you don't want to share, internal hostnames, etc.) before using it in a demo or committing it anywhere.

## Safe demonstration approach for a viva or presentation

- Prefer the automated unit tests (`python -m unittest discover -s tests -v`) to demonstrate detector decisions — they use small, constructed packets and don't depend on live network conditions.
- Only use authorized and sanitized PCAP files for the `analyze` command.
- Do not generate attacks (SYN floods, scans, etc.) against public, workplace, or third-party networks — only against a lab environment you own and control.
- Show threshold tuning in `config.yaml` and explain how/why false positives can occur.
- If you want to show the dashboard with populated data, use clearly labeled demonstration/synthetic data rather than real captured traffic.

## What NOT to commit

Do not commit real `.pcap`/`.pcapng` files, `nids.db`, exported `alerts.json`/`alerts.csv`, or anything containing credentials or personal data. These are already excluded via `.gitignore`.
