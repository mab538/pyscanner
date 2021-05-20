# pyscanner

PyScanner is a basic port scanner built to learn scapy programming in python. Just use nmap. 

# Running the Program

This project uses scapy to send custom packets. You need to run it as root. 

When running with poetry use the following command
```bash
sudo -E env "PATH=$PATH" poetry run pyscanner <csv list of ip addresses or CIDR notation range>
```

# Credits

This package was created by Mike Bosland

# To Dos

- [ ] Add tests
- [ ] Add Dockerfile information
- [ ] Add install instructions
- [ ] Add TCP Connect scanning
- [ ] Add FIN scanning
- [ ] Add XMAS scanning
- [ ] Add UDP scanning
- [ ] Add data models for host, port for easier data display/export
- [ ] Add data export options