How to extend data/lolbins.yaml

This repository ships a curated `data/lolbins.yaml` file that contains common living-off-the-land binaries (LOLbins) and small metadata used by `EndpointHunter`.

Guidelines for safely editing or extending the file:

- Keep entries small and focused. Each entry is a YAML mapping with these recommended keys:
  - name: short program name (e.g., certutil)
  - path_regex: optional regex matching executable path/name
  - cmdline_regex: optional regex matching command-line invocation
  - tags: list of tags like ["download","persistence","encode"]
  - confidence: optional float 0.0-1.0 used to weight the finding

- Prefer anchored regexes (use `^` and `$`), escape spaces, and avoid overly-broad patterns (e.g., `.*`).
- Keep `confidence` conservative for common system utilities (0.2-0.6) and higher for known-malicious variants.
- Add a short comment above new entries explaining the source of the signature and date added.
- Update the `EndpointHunter` loading logic only if you need custom parsing; the loader merges lists and ignores unknown fields.

Example entry:

- name: certutil
  path_regex: "(?i)\\\\windows\\\\system32\\\\certutil\\.exe$"
  cmdline_regex: "(?i)certutil\\s+-encode"
  tags: ["encode","download"]
  confidence: 0.4

Testing and rollout:
- Add unit tests for any complex regexes to avoid accidental false positives.
- Keep additions to `data/lolbins.yaml` in a single PR with tests and changelog notes.
- For large signature lists, consider moving to an external datastore and add caching logic in `EndpointHunter`.
