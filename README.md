# trust-me-bro-jar

Elasticsearch License Forge Tool - generates valid ES licenses signed with your own RSA private key.

Full writeup: [zip -j trust_me_bro.jar - How One Command Cracks Elasticsearch Enterprise](https://www.undefinedbehaviors.com/cracking-elk)

## What this does

Elasticsearch's licensing system trusts a single `public.key` file inside an unsigned JAR archive. Replace it with your own public key, and ES will accept licenses signed with your private key. No code patching, no decompilation, no bytecode modification.

Tested on Elasticsearch 9.3.0 and 8.13.1.

## Requirements

```
pip install cryptography
```

## Usage

### Generate a forged license

```bash
# 1. Generate an RSA-2048 key pair
openssl genrsa -out private.pem 2048

# 2. Extract the public key in DER format (for JAR replacement)
python3 elastic_forge.py extract-pubkey --key private.pem

# 3. Replace public.key inside x-pack-core JAR, restart ES, then:
python3 elastic_forge.py generate \
  --key private.pem \
  --type enterprise \
  --issued-to "My Org" \
  --max-nodes 1000 \
  --days 3650 \
  --output forged_license.json

# 4. Upload
curl -sk -XPUT 'https://localhost:9200/_license?acknowledge=true' \
  -u elastic:password \
  -H 'Content-Type: application/json' \
  -d @forged_license.json
```

### Extract public key only

```bash
python3 elastic_forge.py extract-pubkey --key private.pem --pub-output public.key
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--key` | (required) | Path to RSA private key (PEM) |
| `--type` | `platinum` | License type: `basic`, `trial`, `gold`, `platinum`, `enterprise` |
| `--issued-to` | `CTF Security Research` | Issued to |
| `--issuer` | `elastic-forge` | Issuer name |
| `--max-nodes` | `1000` | Max nodes |
| `--days` | `3650` | Validity in days |
| `--license-version` | `5` | License format version: `3`, `4`, `5` (use 5 for ES 8.x/9.x) |
| `--output` | `forged_license.json` | Output file |

## Disclosure

This research was coordinated with the Elastic security team prior to publication.
