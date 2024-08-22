from setuptools import setup, find_packages

setup(
    name="keyseed",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        "mnemonic",
        "pycryptodome",
        "cryptography"
    ],
    entry_points={
        "console_scripts": [
            "keyseed=keyseed.app:main",
        ],
    },
)
