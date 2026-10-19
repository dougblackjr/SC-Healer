"""Create an inert WordPress-shaped fixture. No working malware or real credentials."""

import argparse
import base64
import gzip
import json
from pathlib import Path
import zipfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('destination', help='New directory; must not already exist')
args = p.parse_args()
base = Path(args.destination).absolute()
base.mkdir(mode=0o700, exist_ok=False)
site = base / 'site'
trusted = base / 'trusted'
trusted.mkdir()

# All potentially suspicious words appear inside PHP comments, never executable code.
payload = b'<?php /* INERT DEMO: SC_AUTO_PREPEND mu-plugins file_put_contents( gzdecode( eth_call all_plugins */\n'
files = {
    'wp-content/shim.php': b'<?php /* inert example prepend */\n',
    'wp-content/.loader.php': payload,
    'wp-content/mu-plugins/demo-kit.php': payload,
    'wp-content/plugins/demo-kit/demo-kit.php': payload,
    'wp-content/db.php': b'<?php /* ' + base64.b64encode(gzip.compress(payload)) + b' */\n',
    'wp-content/themes/demo/functions.php': b'<?php /* Legitimate demo theme. */\n/* SC_BEGIN inert injected block SC_END */\n',
    '.user.ini': b'auto_prepend_file = "' + str(site / 'wp-content/shim.php').encode() + b'"\nmemory_limit = 256M\n',
    'index.php': b'<?php /* Inert demonstration site. */\n',
}
for name, data in files.items():
    path = site / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
with zipfile.ZipFile(site / 'wp-content/abc123def456.zip', 'w') as archive:
    archive.writestr('restore.php', payload)
(trusted / 'functions.php').write_bytes(b'<?php /* Legitimate demo theme. */\n')
(trusted / 'user.ini').write_bytes(b'memory_limit = 256M\n')
print(json.dumps({'site': str(site), 'trusted': str(trusted), 'artifacts': str(base)}, indent=2))
