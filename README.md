# Onion Domain Payload Obfuscation
This project implements a payload obfuscation technique that encodes arbitrary binary data as a sequence of fake Tor v3 .onion domain names.

## How It Works
Each 35-byte chunk of the payload is encoded into a 56-character Base32 string (no padding required, since 35 × 8 = 280 bits, evenly divisible by 5), then suffixed with .onion to produce a string visually indistinguishable from a legitimate Tor v3 hidden service address.

A 4-byte little-endian length header is prepended to the payload before encoding, allowing exact recovery of the original data during decoding.

## Encoding Summary
|    Parameter	         |  Value                 |
|:-----------------------|-----------------------:|
| Bytes per domain       |	35                    |
| Base32 chars per domain|	56                    |
| Domain format          |	<56 chars>.onion      |
| Header	             |4-byte LE payload length|

## Disclaimer
This project is intended for educational and research purposes only. The technique described does not provide encryption — it is purely an encoding scheme. Do not use this code for malicious purposes.