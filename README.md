# SC Healer

A standalone Linux/POSIX recovery CLI for WordPress incidents involving the SC malware family. Run it from a trusted directory **outside WordPress**. It never loads `wp-config.php`, starts PHP, invokes WP-CLI, executes samples, or contacts attacker infrastructure.

This is an initial recovery toolkit, not a promise of automatic eradication. It combines static triage with explicit, reversible file and database remediation. Host isolation and browser recovery are part of the procedure. No actual infected installation or malware samples were supplied for validation; tests use inert fixtures.

## Install and scan

Python 3.10+ is required. File scanning has no runtime dependencies. MySQL operations use the optional PyMySQL dependency.

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[mysql]'
.venv/bin/sc-healer --help

# /srv/recovery must already exist, be private, and be outside ALL web roots.
.venv/bin/sc-healer scan /srv/www/example --output /srv/recovery/files.json
.venv/bin/sc-healer host-audit /srv/www/example --output /srv/recovery/host.json
```

`python3 -m sc_healer` also works directly from this checkout for file operations. JSON reports created by the CLI have mode `0600` and never overwrite existing output files. Scan exit codes: `0` = no known file indicators, `1` = findings to review, `2` = incomplete coverage or error. A zero is **not** a clean bill of health. Host inventory uses `2` for visibility gaps; candidate processes/segments are not classified as malicious.

### What is implemented

| Surface | Inspection | Remediation |
| --- | --- | --- |
| All files, including hidden/padded PHP | Streaming scan of every raw byte; no default file-size cutoff | Explicit quarantine, inert prepend replacement, trusted-file replacement |
| Encoded content and ZIP bundles | Bounded base64/gzip/zlib decoding; archive inspection without extraction | Quarantine the selected containing file |
| MU/normal plugin copies | Matching-content correlation, behavioral clues | Select each confirmed file explicitly |
| Options and multisite options/sitemeta | Direct database scan, decoded-content checks | Selected options deletion; sitemeta requires manual remediation |
| WordPress cron | Parse serialized arrays without PHP or object instantiation | Remove exact selected hooks, preserving other events |
| User persistence | List administrator capability records, including mismatched prefixes | Optional session-token invalidation; accounts require manual review |
| Database triggers/events | Read definitions where database privileges permit | Host/DB administrator reviews and removes confirmed malicious definitions |
| Processes, system cron, System V shared memory | Read-only Linux inventory | Host administrator isolates and clears confirmed persistence |
| Browser service workers/caches | Local JavaScript helper lists exact registrations and cache names | Explicit selection; only the current browser profile/origin is affected |
| Reappearance | Compare repeated scans against a post-cleanup inventory | Report changes; no unattended deletions |
| Blockchain command channel | Collect RPC methods and candidate addresses/selectors/origins, including decoded content | Generate a dedicated-UID nftables containment/rollback bundle |

Names, cache plugins, blockchain usage, prepend directives, and `sc_` prefixes can be legitimate. Findings are evidence to investigate, never deletion instructions. No fixed attacker address, plugin name, IPC key, or random option name is assumed.

## Blockchain-specific containment

SC uses a contract as a changing command-server directory, with public Ethereum RPC gateways providing access. A domain blocklist can become stale when the operator updates the contract. [Imunify analysis](https://blog.imunify360.com/how-sc-wordpress-malware-adapts-to-cleanups/), [Sucuri analysis](https://blog.sucuri.net/2026/09/sc-wordpress-malware-a-self-healing-mesh-of-loaders-drop-ins-and-a-blockchain-controlled-backdoor.html). No site-specific contract/selector/gateway list has been verified for this project.

Recovery does not require modifying the blockchain. Deny the compromised workload access to its control channel, remove the local readers/loaders and persistence, then reopen only after verification. Network containment alone cannot stop offline regeneration from a surviving payload.

`scan` and `db-scan` now include a `blockchain` object on relevant findings. It records RPC methods, candidate 20-byte addresses and four-byte selectors, and co-located HTTP/WebSocket endpoint origins. It inspects bounded decoded payloads and ZIP members too. It never contacts those endpoints or submits a transaction. URL credentials, paths and query strings are omitted from this object to avoid exposing RPC API keys. Other report fields, especially database trigger definitions, can still contain sensitive data.

These are investigation clues: the tool does not establish that an address is a deployed contract, that a selector belongs to it, or that every URL in the same artifact is an RPC gateway. No candidates are automatically turned into block rules. Unreadable/obfuscated strings still require manual analysis. Contract addresses are not IP addresses, and network firewalls cannot identify a contract inside encrypted HTTPS requests.

For emergency Linux containment, generate an outbound-deny plan scoped to the **actual socket-owner UID** used by the site's PHP/background processes. Do not infer it from the site directory owner. This requires a dedicated account; a shared `www-data` identity would affect every workload using it. Shared-hosting users should give the plan to the host operator, who can choose an account/container boundary that is actually isolated.

```bash
# 1201 is an example dedicated PHP UID, not a detected or recommended value.
.venv/bin/sc-healer egress-plan /srv/www/example \
  --uid 1201 --dedicated-uid \
  --output-dir /srv/recovery/egress-001
```

The new private directory contains `plan.json`, `apply.nft`, and `rollback.nft`. **Generation does not install any rules.** The default blocks all IPv4/IPv6 output associated with that UID, including existing connections, DNS, loopback and web responses. Plan for downtime. It does not grant a blanket established-connection exception that could preserve an existing command session. Use a separate recovery identity so containment does not disrupt your own SSH session or recovery tools.

If essential during recovery, add explicit literal-IP, protocol and port exceptions, for example `--allow tcp 192.0.2.10 3306` for a reviewed database endpoint. Documentation addresses are examples only. Hostnames, CIDRs, wildcard destinations and root UID are refused. Every exception weakens isolation; do not allow a generic proxy, recursive DNS resolver or unrestricted HTTPS gateway as a convenience. A Unix database socket is unaffected by an IP firewall, but Unix sockets to forwarding agents also provide a potential bypass.

After inspecting the generated files, the host operator can validate and apply them in the workload's network namespace:

```bash
sudo nft --check --file /srv/recovery/egress-001/apply.nft
sudo nft --file /srv/recovery/egress-001/apply.nft
sudo nft list table inet sc_healer_uid_1201

# After verified recovery, remove only this temporary table:
sudo nft --file /srv/recovery/egress-001/rollback.nft
```

The bundle creates its own `inet` table and refuses to merge into an existing table of the same name. It never flushes the ruleset. Socket UID matching and local-output hooks follow the [nftables metadata](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation) and [chain documentation](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains). Existing firewall restrictions remain in effect.

Verify with a controlled reachable endpoint, short timeouts, both IP families, and the actual unprivileged workload identity. Compare drop counters and confirm unrelated identities still work. Do not probe the attacker. These rules are local-output controls: container traffic forwarded through a host, inherited sockets, other-UID delegates, privileged escapes, and remote administrators' browsers need separate controls. They are not persisted across reboot/firewall-manager reload. Stop malicious execution as well as restricting traffic.

For continued operation after recovery, build a host-managed egress policy around the site's real dependencies. If legitimate blockchain access is essential, enforce an application-aware RPC gateway with allowed chain/contract/method combinations and prevent direct alternate egress. Merely allowing an entire public RPC provider still lets malware call arbitrary contracts. This tool currently generates emergency UID containment, not that production RPC gateway.

## Recovery procedure

### 1. Isolate execution and preserve evidence

Use SSH or a trusted rescue environment. Take a filesystem and database backup. Block public application traffic, stop the affected PHP workers, suspend site cron/external schedulers, and stop confirmed background writers. Restrict outbound access as appropriate for the host. WordPress maintenance mode and `--skip-plugins` do not establish isolation. Coordinate shared services with the host; do not kill every PHP process or delete all shared-memory segments.

Run `scan` and `host-audit`. Inspect `coverage_gaps`, not just `findings`. Inventory every sibling site that shares a writable account. Check parent `.user.ini`/`.htaccess`, server/FPM configuration, custom WordPress content paths, and external includes separately. The scanner follows no symlinks and reports them as gaps.

The apply flags record operator assertions. **They do not stop services or prove execution has stopped.** Active hostile writers can race ordinary filesystem operations; do not apply a plan on a running compromised site.

### 2. Inspect and clear database/host persistence

Create a private connection file outside all web roots, copying the connection details manually from configuration. Do not execute the site's PHP to discover credentials.

```json
{
  "unix_socket": "/run/mysqld/mysqld.sock",
  "user": "recovery_operator",
  "password": "YOUR_DATABASE_PASSWORD",
  "database": "wordpress",
  "prefix": "wp_"
}
```

Use `chmod 600 /srv/recovery/db-config.json`. For TCP connections, `host` and `port` are supported. Non-loopback TCP requires `ssl_ca`; certificate and hostname verification are enabled. Prefixes and database identifiers must contain only ASCII letters, digits, and underscores.

```bash
.venv/bin/sc-healer db-scan \
  --root /srv/www/example --config /srv/recovery/db-config.json \
  --output /srv/recovery/database.json
```

Review every trigger/event with a database administrator; insufficient privileges can hide definitions without an error. Preserve definitions before dropping confirmed malicious ones. Audit capabilities directly, verify account ownership, remove confirmed unauthorized accounts while preserving/reassigning legitimate content, and inspect other tables that the scanner does not cover. Neither an administrator role nor `wp_capabilities` alone proves an account is malicious.

Clear confirmed malicious shared-memory segments and scheduled jobs through the host. The inventory includes other owners' visible IPC metadata because persistence can cross account boundaries. It does not read segment contents or decide which segments are safe to delete. Check other process/IPC namespaces and schedulers when applicable.

Build a database plan using actual row IDs and hook names from your investigation. These names and IDs are examples:

```bash
.venv/bin/sc-healer db-plan \
  --root /srv/www/example --config /srv/recovery/db-config.json \
  --delete-option wp_options:123 \
  --remove-cron-hook wp_options:confirmed_malicious_hook \
  --invalidate-sessions --output /srv/recovery/db-plan.json

# Review db-plan.json before applying. It contains sensitive original row data.
.venv/bin/sc-healer db-apply /srv/recovery/db-plan.json \
  --root /srv/www/example --config /srv/recovery/db-config.json \
  --backup /srv/recovery/db-backup.json \
  --execution-stopped --triggers-reviewed
```

Database apply locks and verifies all selected rows, writes a durable private backup, and uses one InnoDB transaction. Other storage engines are refused. A stale row aborts the entire operation. Object/reference-bearing or malformed PHP serialization is refused. For multisite, specify each affected options table and hook explicitly; base usermeta session invalidation covers the configured network. A differently located/custom user table needs a separate review.

Flush affected persistent object caches through the trusted host service after database cleanup and before reopening. Deleting database session tokens alone is insufficient when forged authentication cookies or cached tokens are possible: rotate WordPress authentication keys/salts and affected credentials as well.

### 3. Apply a reviewed file plan

Prepare clean copies of affected theme/configuration files outside the site. Obtain pristine core/plugin/theme files from trusted vendor packages or a verified pre-compromise backup. Keep legitimate customizations. The tool deliberately does not regex-cut arbitrary PHP blocks: duplicate markers and PHP open/close boundaries can make that corrupt a theme.

For a confirmed malicious prepend, select `--neutralize-prepend` on its PHP target and replace the affected configuration with a reviewed clean version. Keep the inert target in place through the relevant PHP configuration/opcode cache reset. Do not delete a prepend target while cached configuration still refers to it. Legitimate security products also use prepend directives.

```bash
.venv/bin/sc-healer plan /srv/www/example \
  --neutralize-prepend wp-content/confirmed-shim.php \
  --replace .user.ini /srv/recovery/clean-user.ini \
  --replace wp-content/themes/my-theme/functions.php /srv/recovery/clean-functions.php \
  --quarantine wp-content/.confirmed-loader.php \
  --quarantine wp-content/mu-plugins/confirmed-fake-plugin.php \
  --quarantine wp-content/plugins/confirmed-fake-plugin/confirmed-fake-plugin.php \
  --quarantine wp-content/confirmed-restore-bundle.zip \
  --output /srv/recovery/file-plan.json

# Review paths, hashes, and replacement contents in file-plan.json.
.venv/bin/sc-healer apply /srv/recovery/file-plan.json \
  --evidence-dir /srv/recovery/run-001 \
  --execution-stopped --off-disk-reviewed
```

Include **every** confirmed component, including compromised drop-ins and encoded cache stubs. Use trusted replacements when a file also serves a legitimate purpose. Quarantine moves content into private evidence by backing it up and removing the selected original; it does not recursively remove plugin directories. Each file must be selected. An entry inside an archive is reported as `archive.zip::member`; select the archive itself for quarantine.

All originals are backed up before the first mutation. Neutralizations precede replacements and quarantines. The plan rejects changed content, symlinks, multiple hard links, and duplicate selections. File replacement is atomic per file, but the entire filesystem operation is **not** one transaction. A durable journal supports recovery after interruption. If interrupted, keep execution stopped and inspect the journal before proceeding.

Modes and ownership are preserved for replacements; restoration also restores recorded timestamps. Extended attributes, ACLs, SELinux labels, and filesystem-specific metadata are not preserved. Use your full filesystem backup and host tooling where those matter. File planning/backup currently holds selected file contents in memory; batch extremely large selections on a suitably sized rescue host.

### 4. Recover administrator browsers

Keep sessions invalidated and the server isolated. For every affected HTTPS origin and each administrator's browser profile/device, use the browser's Application/Storage tools to inspect registrations and clear confirmed malicious workers and storage. A clean new profile does not repair an old profile. Close all existing site tabs/windows.

The optional [browser helper](browser/cleanup.js) can be run from a trusted local copy in DevTools on the affected origin. Enable the browser's service-worker bypass/offline controls while investigating. A compromised page or service worker may tamper with page APIs or intercepted helper pages; do not trust a helper served through the infected site as proof of cleanup. Native browser storage controls are the fallback.

```javascript
await scHealerBrowser.inspect()

// Copy only confirmed malicious entries from inspect(), preserving exact URLs.
await scHealerBrowser.removeWorkers([
  {scope: "https://example.com/", scriptURLs: ["https://example.com/confirmed-bad-worker.js"]}
])
await scHealerBrowser.removeCaches(["confirmed-malicious-cache-name"])
```

The helper does not infer that a root-scoped worker is malicious, fetch scripts, register workers, or remove all caches. Unregistering is a request: active pages and in-flight work may survive it. Close every tab/window for that origin and verify again before logging in.

### 5. Rebuild trust, verify, then reopen

Patch or replace the vulnerable entry point and affected dependencies. Verify core/plugins/themes against trusted distributions, rotate all potentially exposed credentials and WordPress salts, and remove unauthorized accounts. Restart/reset the affected PHP workers and opcode/config caches through the host; clear persistent object caches. Confirm malicious triggers, schedulers, and IPC sources have been addressed.

```bash
.venv/bin/sc-healer scan /srv/www/example --output /srv/recovery/after.json
.venv/bin/sc-healer db-scan \
  --root /srv/www/example --config /srv/recovery/db-config.json \
  --output /srv/recovery/database-after.json
.venv/bin/sc-healer watch /srv/www/example \
  --baseline /srv/recovery/after.json --interval 30 --iterations 20
```

Review remaining findings and finish coverage gaps before reopening. A watch baseline must have no file coverage gaps, but it may still contain findings: the operator must review those. `watch` reports any added/changed/removed file and exits `1`, including legitimate cache activity. It exits `2` for incomplete coverage. It does not monitor the database or browsers, and changes that appear/disappear between scans can be missed. Start with controlled traffic from a clean browser, then continue monitoring through normal scheduler activity. A recurrence means recovery is unfinished.

## Rollback

Rollback intentionally restores original, potentially malicious content. Keep all execution stopped. Never restore an old session backup to a reopened site.

```bash
.venv/bin/sc-healer restore /srv/recovery/run-001/journal.json --execution-stopped
.venv/bin/sc-healer db-restore /srv/recovery/db-backup.json \
  --root /srv/www/example --config /srv/recovery/db-config.json \
  --execution-stopped --triggers-reviewed
```

Restoration checks backup hashes and current content before overwriting. If a file/row changed after cleanup, it refuses instead of discarding newer data. A database backup with state `prepared` may represent a committed or rolled-back transaction after a crash; restoration checks actual row states. A file journal in `backing-up` means site changes had not started. Recovery is idempotent for already restored original content.

## Try an inert demo

The demo creates comments containing detection indicators, never working malware. Choose a destination that does not exist:

```bash
python3 examples/make_demo.py /tmp/sc-healer-demo
python3 -m sc_healer scan /tmp/sc-healer-demo/site --output /tmp/sc-healer-demo/before.json
# Exit 1 is expected: the inert indicators are detected.

python3 -m sc_healer plan /tmp/sc-healer-demo/site \
  --neutralize-prepend wp-content/shim.php \
  --replace .user.ini /tmp/sc-healer-demo/trusted/user.ini \
  --replace wp-content/themes/demo/functions.php /tmp/sc-healer-demo/trusted/functions.php \
  --quarantine wp-content/.loader.php \
  --quarantine wp-content/db.php \
  --quarantine wp-content/mu-plugins/demo-kit.php \
  --quarantine wp-content/plugins/demo-kit/demo-kit.php \
  --quarantine wp-content/abc123def456.zip \
  --output /tmp/sc-healer-demo/plan.json
python3 -m sc_healer apply /tmp/sc-healer-demo/plan.json \
  --evidence-dir /tmp/sc-healer-demo/evidence \
  --execution-stopped --off-disk-reviewed
python3 -m sc_healer scan /tmp/sc-healer-demo/site --output /tmp/sc-healer-demo/after.json
python3 -m sc_healer restore /tmp/sc-healer-demo/evidence/journal.json --execution-stopped
```

## Tests and limits

```bash
python3 -m unittest discover -s tests -v
node --test tests/browser.test.cjs

# Optional: starts and stops its own socket-only temporary MySQL 8 instance.
# Does not connect to the host's existing database.
SC_HEALER_MYSQL_TEST=1 .venv/bin/python -m unittest discover -s tests -v

# Optional Linux kernel test: disposable user/network namespace, local sockets only.
# Requires nft, ip, unshare, and permission to create unprivileged user namespaces.
SC_HEALER_NFT_TEST=1 python3 -m unittest discover -s tests -p test_blockchain.py -v
```

Coverage includes a 29 MiB padded file, chunk boundaries, encoded payloads, ZIP traversal, decompression limits, legitimate cache code, stale plans, symlinks/hard links, interrupted cleanup, backup corruption, Unicode cron serialization, selective browser removal, and real MySQL transactions/rollback.

The detector uses interpretable string/behavior combinations, not a PHP interpreter or a general deobfuscator. Fully encoded string-table variants can evade it. Raw file scanning is complete only for readable regular files under the supplied root. Decoding has depth/output/candidate limits; ZIP members have size/count limits, nested archives are not expanded, and every reached limit becomes a coverage gap. Non-ZIP archive formats and non-base64 encodings are not decoded. Database scanning covers selected WordPress persistence surfaces, not arbitrary tables; values larger than 16 MiB are flagged as uninspected. A scan cannot establish whether an entire account or host is trustworthy.

## Research references

The design responds to the coordinated persistence described by [Sucuri](https://blog.sucuri.net/2026/09/sc-wordpress-malware-a-self-healing-mesh-of-loaders-drop-ins-and-a-blockchain-controlled-backdoor.html) and the newer database/browser adaptations described by [Imunify](https://blog.imunify360.com/how-sc-wordpress-malware-adapts-to-cleanups/). These reports motivated coverage across disk, database, runtime, and browser state instead of an in-WordPress removal plugin.

PHP documents the per-directory configuration cache in its [.user.ini reference](https://www.php.net/manual/en/configuration.file.per-user.php). Browser cleanup behavior follows [ServiceWorkerRegistration.unregister](https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerRegistration/unregister); a successful result alone does not prove ongoing worker activity has ended. See also [Imunify's browser cleanup analysis](https://blog.imunify360.com/imunify360-removes-malicious-service-workers/).
