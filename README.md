# Shodan-to-POC-and-Solution
Shodan.io Query to POC and Nessus Solution

Shodan to POC is a tool that takes a search query or input file of IP addresses and runs it against Shodan. The tool parses the results to extract data such as IP address, hostname, port, and vulnerabilities. The CVEs (Common Vulnerabilities and Exposures) are identified, and the associated CVSS score and description are retrieved from Shodan's data. Shodan to POC then uses the CVE data to search for proof-of-concept (POC) exploits through various sources such as ExploitDB, Rapid7, Trickest, and InTheWild. Finally, the tool searches Nessus for viable solutions using the CVE data.
