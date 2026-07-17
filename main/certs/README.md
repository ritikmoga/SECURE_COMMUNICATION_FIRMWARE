These files are placeholders. Run:

python tools/generate_dev_pki.py --devices alice bob --relay-host <relay-ip>
python tools/configure_device.py --device alice --peers bob

The configure script replaces:
- relay_ca.crt
- client.crt
- client.key
- identity.key
