# keyseed
Generate mnemonic RSA and Ed25519 keys. Restore keys from seed phrase

## Instalation
```
pip install git+https://github.com/sky-rope/keyseed.git@1.0
```

## Usage
Generates keys:
```
keyseed create
```
Retrieve existing key from seed phrase:
```
keyseed recover
```

For ssh convert public key from PEM RSA to openssh
```
ssh-keygen -y -f /path/to/private_key > /path/to/public_key.pub
```