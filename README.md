# AUTONETIX

AUTONETIX is a tool designed for subdomain enumeration using Sublist3r and Subfinder and subsequent vulnerability scanning using the Acunetix API. This script is designed to provide results on the vulnerabilities contained in the subdomains of each of the domains provided to the tool without the need for user intervention. Possible uses in Bug Bounty, CVE discovery and mass vulnerability scanning.

For each of the domains provided, subdomains will be listed using the tools specified above and only the unique domains found will be scanned by Acunetix. The status of the scan will be checked every 30 seconds and reported on the terminal. Finally, when finished, all vulnerabilities found will be printed on the terminal in order of criticality and the scans will be removed from acunetix to avoid the accumulation of scans in the program.

PS: Make sure that a valid Acunetix API is entered in the code and verify that the specified URL corresponds to your Acunetix installation.

## Prerequisites

- Sublist3r:

```shell
sudo apt install sublist3r 
```
- subfinder:
```shell
sudo apt install subfinder
```
- jq:
```shell
sudo apt install jq
```
- curl:
```shell
sudo apt install curl
```

## Installation
Clone the repository:
```shell
git clone https://github.com/G4sul1n/Autonetix.git
```
```shell
cd autonetix
```
## Usage
1. Make the script executable:
```shell
chmod +x autonetix.sh
```
2. Add your valid Acunetix API in the code.
3. Verify that the specified URL in the code corresponds to your Acunetix installation.
4. Run the script:
```shell
./autonetix.sh -d domain1.com, domain2.com, domain3.com...
```
PS: Please note that subdomain discovery may take some time. Do not alarm if you don't see results in your screen inmediately.
## Screenshots
![autonetix example](https://github.com/user-attachments/assets/4c6aa6cf-eb64-4635-a2b3-32b1344f7e9d)
![autonetix result](https://github.com/user-attachments/assets/4730ead7-5f9c-4528-9c22-0a2118a9fffc)
