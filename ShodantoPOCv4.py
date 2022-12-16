#!/usr/bin/env python
"""

        Title: Shodan to POC/Solution Script
        Created by: Chris Armour
        Last Update Date: 12-5-2022
        Version: 4.0
        Description: This script will take a search query or input file of IP address and run it against Shodan.
        It will then take the results and parse out the data for IP address, Hostname, Port, and Vulns.
        The CVE's CVSS Score and Description is pulled from the Shodan Data
        The script will then take the CVE's and search for a POC through ExploitDB, Rapid7, Trickest and InTheWild.
        The Script will then use the CVE's data to search Nessus for viable solutions.

        Help Menu:
            -h, --help: Show this help menu
            Nessus Solution Database Update: (REQUIRED TO RUN SCRIPT https://www.tenable.com/tenable-for-education/nessus-essentials VM can be used)
                Example: python3 <scriptfile> -u -n 192.168.0.2:8834 -a <access key> -s <secret key>
                -u, --update: Nessus IP or Hostname default is http://localhost:8834
                -a, --access: Nessus Access Key
                -s, --secret: Nessus Secret Key
            
            Search Types:
                Query Search:
                    Example: python3 <scriptfile> -q "port:22 has_vuln:true" -o output.json
                    -q, --query: Search Shodan with a query
                    -o, --output: Output file name
                    -l, --limit: Limit the number of results

                File Host Search:
                    Example: python3 <scriptfile> -i input.txt -o output.json -x true
                    -i, --input: Input file of IP addresses to search Shodan
                    -o, --output: Output file name
                    -x, --history: Search Shodan History for the IP address

                Individual Host Search:
                    Example: python3 <scriptfile> -H 8.8.8.8 -o output.json -x true
                    -H, --host: Search Shodan with a single IP address
                    -o, --output: Output file name
                    -x, --history: Search Shodan History for the IP address


"""


import argparse
import shodan
from shodan import Shodan
from shodan.helpers import open_file, write_banner
from shodan.cli.helpers import get_api_key
import json
import requests
import asyncio
from aiohttp import ClientSession
import os


def nessusCheck():
    if os.path.exists('NessusDB.json'):
        print('Nessus: Database Found')
        print('Nessus: Loading Database')
        with open('NessusDB.json') as f:
            DATA = json.load(f)
        print('Nessus: Database Loaded')
        return DATA
    else:
        print('Nessus: Database Not Found')
        exit()

async def cve_fetch(cve, url, parm, session):
    async_results = []
    async with session.get(url) as response:
        # print('Processing: ' + url)
        # Check if "reports in text"
        if parm in await response.text():
            async_results.append({cve: url})

        await response.read()
        return async_results

async def cve_bound(sem,cve, url,parm, session):
    # Getter function with semaphore.
    async with sem:
       response = await cve_fetch(cve,url,parm, session)
    return response



async def cve_processor(cve_list, url, parm):
    tasks = []
    # create instance of Semaphore
    sem = asyncio.Semaphore(10)
    # Create client session that will ensure we dont open new connection
    # per each request.

    async with ClientSession() as session:
        async_results =[]
        for i in cve_list:
            # pass Semaphore and session to every GET request
            # Check is trickiest is not in url
            newURL = ''
            if 'https://github.com/trickest/cve/blob/main/{cveYear}/{cve}.md' == url:
                cve_Year = i.split('-')[1]
                newURL = url.format(cveYear= cve_Year, cve = i)

            else:
                newURL = url.format(i)


            task = asyncio.ensure_future(cve_bound(sem,i, newURL,  parm, session))


            # where do headers
            tasks.append(task)

        responses = asyncio.gather(*tasks)
        await responses
        # append the non empty responses to the async_results list
        for response in responses.result():
            if response:
                async_results.append(response[0])
    return async_results

async def nessus_Processor(DATA, cve):
    
    
    print('Nessus: Processing: ' + cve)
    nessus_solutions = []
    nessus_prepared = {}
    for plugin in DATA:
        plugin_solution = ''
        # Print the Plugin ID
        for attribute in plugin['attributes']:
            if attribute['attribute_name'] == 'solution':
                plugin_solution = attribute['attribute_value']
            if attribute['attribute_name'] == 'cve':
                if attribute['attribute_value'] == cve:
                    nessus_solutions.append({'Plugin ID': plugin['id'], 'Plugin Name': plugin['name'], 'Solution': plugin_solution})
    nessus_prepared[cve] = nessus_solutions

    return nessus_prepared

async def nessus_bound(DATA, sem, cve):
    async with sem:
        response = await nessus_Processor(DATA, cve)
    return response

async def nessusSearch(DATA, cve_list):
    nessus_results = []
    tasks = []
    # # create instance of Semaphore
    sem = asyncio.Semaphore(1000)
    for cve in cve_list:
        task = nessus_bound(DATA, sem, cve)
        tasks.append(task)

    responses = asyncio.gather(*tasks)
    await responses
    for response in responses.result():
        if response:
            nessus_results.append(response)

    return nessus_results


def retriveCVE(DATA, cve_list):
    rapid7 = []
    exploitdb = []
    inthewild = []
    trickiest = []
    nessus = {}
    # Nessus

    # Loop through the CVE's and get the POC's

    print('Processing Nessus')
    nessus = asyncio.run(nessusSearch(DATA, cve_list))
    print('Nessus Data Collected')
    print('Processing Exploit DB')
    exploitDB_url = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'
    # ExploitDB csv file
    exploitDB_data = requests.get(exploitDB_url)
    # Parse the csv file
    exploitDB_data = exploitDB_data.text.splitlines()
    # check if the cve is in the csv file in column 11
    # if it is then get the exploit id in column 0
    for cve in cve_list:
        # Print the CVE out of Total
        #print('Exploit DB: Processing CVE: ' + cve + ' [Number: ' + str(cve_list.index(cve) + 1) + ' of ' + str(len(cve_list)) + ']')
        for line in exploitDB_data:
            if cve in line:
                exploitdb.append({ cve : { 'Exploit': line.split(',')[0], 'url': 'https://www.exploit-db.com/exploits/'+ line.split(',')[0]}})
    # print(exploitdb)
    print('ExploitDB Data Collected')

    print('Processing In The Wild')
    url = "https://inthewild.io/vuln/{}"
    parm = "Reports"
    inthewild = asyncio.run(cve_processor(cve_list, url, parm))


    print('InTheWild Data Collected')

    print('Processing Rapid7')
    url2 = "https://www.rapid7.com/db/?q={}&type=metasploit"
    parm2= "No results"
    rapid7 = asyncio.run(cve_processor(cve_list, url2, parm2))

    print('Rapid7 Data Collected')

    print('Processing Trickest')
    url3 = "https://github.com/trickest/cve/blob/main/{cveYear}/{cve}.md"
    parm3 = "No PoCs from references."
    trickiest = asyncio.run(cve_processor(cve_list, url3, parm3))

    print('Trickest Data Collected')





    return rapid7, exploitdb, inthewild, trickiest, nessus

    # Get the CVE 
def vulnProcessor(result, rapid7, exploitdb, inthewild, trickiest, nessus, vulnKeys):
    vuln_data = []
            # Json Format
            # "vulns": {
            #     "CVE-2019-0708": {
            #         "cvss": 7.5,
            #         "description": "Microsoft Remote Desktop Services (RDS) Remote Code Execution Vulnerability (CVE-2019-0708)",
            #         "POC":{
            #               "Rapid7": "https://www.rapid7.com/db/?q=CVE-2019-0708&type=metasploit",
            #               "ExploitDB": "https://www.exploit-db.com/search?cve=CVE-2019-0708",
            #               "InTheWild": "https://inthewild.io/vuln/CVE-2019-0708",
            #               "Trickiest": "https://github.com/trickest/cve/blob/main/2019/CVE-2019-0708.md"
            #               }
            #         "Solution": {
            #              "Nessus URL": "https://www.tenable.com/plugins/nessus/139907",
            #             "Nessus Solution": "The remote Windows host is missing a security update issued by Microsoft on May 14, 2019. It is, therefore, affected by a remote code execution vulnerability due to improper validation of user-supplied data. An unauthenticated, remote attacker can exploit this, via a specially crafted RDP packet, to execute arbitrary code on the target system. An attacker must first convince a user to connect to the target system using RDP. Failed exploit attempts will result in a denial-of-service condition."
            #          }
            #    }
            # 
            # }

            # Loop through the vulns keys
    for vuln in vulnKeys:
                # Get the CVE
        cve = vuln
                # Get the CVSS Score
        cvss = result['vulns'][vuln]['cvss']

                # Get the CVE Description
        cve_desc = result['vulns'][vuln]['summary']


                # Get the POC's and Solutions
        rapid7_poc ={}
        exploitdb_poc = []
        inthewild_poc = {}
        trickiest_poc = {}
        nessus_solution = []


                # Loop through the rapid7 list
        for rapid7_cve in rapid7:
                    # Check if the cve is in the list
            if cve in rapid7_cve:
                        # Get the URL
                rapid7_poc = rapid7_cve[cve]

                # Loop through the exploitdb list
        for exploitdb_data in exploitdb:
            for key, value in exploitdb_data.items():
                if key == cve:
                    exploitdb_poc.append(value)
                
                # Loop through the inthewild list

        for inthewild_cve in inthewild:
                    # Check if the cve is in the list
            if cve in inthewild_cve:
                        # Get the URL
                inthewild_poc = inthewild_cve[cve]



                # Loop through the trickiest list
        for trickiest_cve in trickiest:
                    # Check if the cve is in the list
            if cve in trickiest_cve:
                        # Get the URL
                trickiest_poc = trickiest_cve[cve]
                
                # Loop through the nessus list
        for nessus_data in nessus:
            for key, value in nessus_data.items():
                if key == cve:
                    nessus_solution.append(value)




                # Append the data to output_list matching the json format
        vuln_data.append({'CVE': cve, 'CVSS': cvss, 'Description': cve_desc, 'POC': {'Rapid7': rapid7_poc, 'ExploitDB': exploitdb_poc, 'InTheWild': inthewild_poc, 'Trickiest': trickiest_poc}, 'Solution': nessus_solution})
    return vuln_data



def search_query(DATA,query, api_key, set_limit, output_file):
    # Setup the Shodan API
    api = shodan.Shodan(api_key)
    # Wrap the query in quotes to make it a phrase search
    # Perform the search

    try:
        # Print Searching Shodan with query
        print('Searching Shodan with query: [ {} ]'.format(query))
        # Search Shodan
        results = api.search(query, limit=set_limit)

        
        print('Shodan api request Complete')
        # For Testing
        # print(results)

        # Get a list of all the CVE's
        cve_list = []
        for result in results['matches']:
            for cve in result['vulns']:
                # check if the cve is already in the list
                if cve not in cve_list:
                    cve_list.append(cve)

        # Remove Duplicates
        cve_list = list(dict.fromkeys(cve_list))
        # Order the CVE's
        cve_list.sort()
    
        # Get the CVE's POC's and Solutions
        rapid7, exploitdb, inthewild, trickiest, nessus = retriveCVE(DATA, cve_list)
        # Construct the output
        output_list = []

        # Loop through the results and get the data
        for result in results['matches']:
            # Show processing
            print('Processing: ' + result['ip_str'] + ' [Number: ' + str(results['matches'].index(result) + 1) + ' of ' + str(len(results['matches'])) + ']')
            # Shodan Link
            shodan_link = 'https://www.shodan.io/host/' + result['ip_str']
            # Get the IP address
            ip = result['ip_str']
            # Get the Hostname
            hostname = result['hostnames']
            # Get the Port
            port = result['port']

            # set the vulns keys to variable vulnKeys
            vulnKeys = result['vulns'].keys()

            vuln_data = vulnProcessor(result, rapid7, exploitdb, inthewild, trickiest, nessus, vulnKeys)


            # Append the data to output
            output_list.append({'data':{'Shodan Link': shodan_link, 'IP' : ip,'Hostname(s)' : hostname, 'Port(s)': port, 'Vulns': vuln_data}})

            # check if output file argument is set
            if output_file:
                # write the output to a file
                with open(output_file, 'w') as f:
                    f.write(json.dumps(output_list, indent=4))
            else:
                # Print the output
                print(json.dumps(output_list, indent=4))
                






    
    except shodan.APIError as e:
        print('Error: {}'.format(e))
    


def host_cve_processor(results):
    vulns = {}
    vulns_prepared = {}
    for result in results['data']:
        try:
            vulns.update(result['vulns'])
        except:
            pass
    vulns_prepared['vulns'] = vulns
    #return vulns_prepared
    return vulns_prepared


def search_host(DATA, host_name, api_key, output_file, use_history):
    # Setup the Shodan API
    api = shodan.Shodan(api_key)
    try:
        print('Searching Shodan for host: [ {} ]'.format(host_name))
        # Search Shodan
        results = api.host(host_name, history=use_history)
        print('Shodan api request Complete')
 # Get a list of all the CVE's
        cve_list = []
        for cve in results['vulns']:
            # check if the cve is already in the list
            if cve not in cve_list:
                cve_list.append(cve)

        # Remove Duplicates
        cve_list = list(dict.fromkeys(cve_list))
        # Order the CVE's
        cve_list.sort()
    
        # Get the CVE's POC's and Solutions
        rapid7, exploitdb, inthewild, trickiest, nessus = retriveCVE(DATA,cve_list)
        # Construct the output
        output_list = []

        # Shodan Link
        shodan_link = 'https://www.shodan.io/host/' + results['ip_str']
        # Get the IP address
        ip = results['ip_str']
        # Get the Hostname
        hostname = results['hostnames']
        # Get the Port
        port = results['ports']

        # set the vulns keys to variable vulnKeys
        vulnKeys = results['vulns']

        cve_prepared = host_cve_processor(results)
        vuln_data = vulnProcessor(cve_prepared, rapid7, exploitdb, inthewild, trickiest, nessus, vulnKeys)


        # Append the data to output
        output_list.append({'data':{'Shodan Link': shodan_link, 'IP' : ip,'Hostname(s)' : hostname, 'Port(s)': port, 'Vulns': vuln_data}})

        # check if output file argument is set
        if output_file:
            # write the output to a file
            with open(output_file, 'w') as f:
                f.write(json.dumps(output_list, indent=4))
        else:
            # Print the output
            print(json.dumps(output_list, indent=4))

    
    except shodan.APIError as e:
        print('Error: {}'.format(e))
        



def search_file(DATA, input_file, api_key, output_file, use_history):
    # Setup the Shodan API
    api = shodan.Shodan(api_key)
    print('Searching Shodan for hosts in file: [ {} ]'.format(input_file))

    try:
        # Construct the output
        output_list = []
        results = []
        results2 = []
        # Open the file and set the hosts to a list variable
        with open(input_file, 'r') as f:
            hosts = f.readlines()
        # Get the number of hosts
        host_count = len(hosts)
        
        for host_name in hosts:
            # Display the current progress of the search out of the total number of hosts
            print('\nProcessing: ' + host_name.strip() + ' [Number: ' + str(hosts.index(host_name) + 1) + ' of ' + str(host_count) + ']')
            try:
                # Search Shodan
                # results.append(api.host(host_name.strip(), history=use_history))

                # For each host get  the ip address, hostname, ports and vulns
                result = api.host(host_name.strip(), history=use_history)

                # check if result['vulns'] exists
                if 'vulns' in result:
                  
                    results2.append(result)
                    new_result = {}
                    new_result['ip_str'] = result['ip_str']
                    new_result['hostnames'] = result['hostnames']
                    new_result['ports'] = result['ports']

                    new_result['vulns'] = result['vulns']
        
                    new_result['data'] = []
                    # for each data point in data check if 'vulns' is in the data point
                    for data in result['data']:
                        if 'vulns' in data:
                            new_result['data'].append({'vulns': data['vulns']})
                    results.append(new_result)
                    print('\tShodan api request Complete')
                else:
                    print('\tNo vulns found')
            except shodan.APIError as e:
                print('No vulns found for host: [ {} ]'.format(host_name.strip()))
                pass

        cve_list = []
        for result in results:
            for cve in result['vulns']:
                # check if the cve is already in the list
                if cve not in cve_list:
                    cve_list.append(cve)
        # Remove Duplicates
        cve_list = list(dict.fromkeys(cve_list))
        # Order the CVE's
        cve_list.sort()
            # Get the CVE's POC's and Solutions
        rapid7, exploitdb, inthewild, trickiest, nessus = retriveCVE(DATA,cve_list) 
        
        for result in results:
            # Show processing
            print('Processing: ' + result['ip_str'] + ' [Number: ' + str(results.index(result) + 1) + ' of ' + str(len(results)) + ']')
            # Shodan Link
            shodan_link = 'https://www.shodan.io/host/' + result['ip_str']
            # Get the IP address
            ip = result['ip_str']
            # Get the Hostname
            hostname = result['hostnames']
            # Get the Port
            port = result['ports']

            # set the vulns keys to variable vulnKeys
            vulnKeys = result['vulns']
            cve_prepared = host_cve_processor(result)
            vuln_data = vulnProcessor(cve_prepared, rapid7, exploitdb, inthewild, trickiest, nessus, vulnKeys)


            # Append the data to output
            output_list.append({'data':{'Shodan Link': shodan_link, 'IP' : ip,'Hostname(s)' : hostname, 'Port(s)': port, 'Vulns': vuln_data}})    
        
        
        
        
        
        # check if output file argument is set
        if output_file:
            # write the output to a file
            with open(output_file, 'w') as f:
                f.write(json.dumps(output_list, indent=4))
        else:
            # Print the output
            print(json.dumps(output_list, indent=4))
    except shodan.APIError as e:
        print('Error: {}'.format(e))

api_results = []
api_tracker = 0

def nessus_requestFamilies(accessKey, secretKey, hostname):
    print('Requesting Nessus Families')
    local_families = []
    # Request A list of Nessus Families using API
    url = '{}/plugins/families/'.format(hostname)

    headers = {
        "accept": "application/json",
        "X-ApiKeys": "accessKey="+ accessKey + ";secretKey=" + secretKey
    }

    local_families = requests.get(url, headers=headers, verify=False).json()
    print('Done Requesting Nessus Families')
    return local_families

def nessus_requestPlugins(accessKey, secretKey,hostname, nessusFamilies):
    print('Requesting Nessus Plugins')
    nessusPluginsList = []
    # # For each Nessus Family 'id', request a list of plugins
    for family in nessusFamilies['families']:
        url = '{hostname}/plugins/families/{familyID}'.format(hostname=hostname, familyID=str(family['id']))


        headers = {
            "accept": "application/json",
            "X-ApiKeys": "accessKey="+ accessKey + ";secretKey=" + secretKey
        }

        # Add Results to the Plugin Dictionary
        # Append the list of plugins to the nessusPluginsList
        nessusPluginsList.append(requests.get(url, headers=headers, verify=False).json())

    pluginids = []
    for plugin in nessusPluginsList:
        for pluginid in plugin['plugins']:
            pluginids.append(pluginid['id'])
    print('Done Requesting Nessus Plugins')
    
    
    return pluginids
    # For each Nessus Plugin 'id', request the plugin details usin


async def nessus_api_fetch(accessKey, secretKey, url, session, pluginids):
    global api_results
    headers = {
    "accept": "application/json",
    "X-ApiKeys": "accessKey="+ accessKey + ";secretKey=" + secretKey
    }
    async with session.get(url, headers=headers, ssl=False) as response:

        api_results.append(await response.json())
        # # print when every 1000 requests are done
        if len(api_results) % 1000 == 0:
            global api_tracker  
            api_tracker = api_tracker + 1000
            # Print the number of requests done and the number of requests left to do keep track of progress using the api_tracker variable
            print('Requests Done: ' + str(api_tracker) + ' Requests Left: ' + str(len(pluginids) - api_tracker) + ' Total Requests: ' + str(len(pluginids)))

            # # write to file every 1000 requests
            with open('NessusDB.json', mode="r+" ) as outfile:
                outfile.seek(os.stat('NessusDB.json').st_size - 1)
                if api_tracker == 1000:
                    outfile.write(json.dumps(api_results, indent=4))
                else:

                    outfile.write( ',{}'.format(json.dumps(api_results, indent=4)[1:]))
                api_results.clear()

        return await response.read()



async def nessus_api_bound_fetch(accessKey, secretKey, sem, url, session, pluginids):
    # Getter function with semaphore.
    
    async with sem:
        await nessus_api_fetch(accessKey, secretKey, url, session, pluginids)


async def nessus_api_update_run(accessKey, secretKey, hostname):
    global api_results
    # Check if the file exists
    # if it does delete it and start over
    if os.path.exists('NessusDB.json'):
        print('Deleting NessusDB.json')
        os.remove('NessusDB.json')
        print('Done Deleting NessusDB.json')
        # create a new file
    with open('NessusDB.json', 'w') as outfile:
        outfile.write(' ')
    

    nessusPluginsID = nessus_requestPlugins(accessKey, secretKey, hostname, nessus_requestFamilies(accessKey, secretKey,hostname))
    url_prepend = '{}/plugins/plugin/'.format(hostname)
    url = url_prepend + '{}'
    tasks = []
    # create instance of Semaphore
    sem = asyncio.Semaphore(10000)

    # Create client session that will ensure we dont open new connection
    # per each request.
    print('Requesting Nessus Plugin Details')
    async with ClientSession() as session:
        for i in nessusPluginsID:
            # pass Semaphore and session to every GET request
            task = asyncio.ensure_future(nessus_api_bound_fetch(accessKey, secretKey, sem, url.format(i),  session, nessusPluginsID))
            # where do headers
            tasks.append(task)

        responses = asyncio.gather(*tasks)
        await responses
    print('Done Requesting Nessus Plugin Details')
    # appending the last results
    with open('NessusDB.json', mode="r+" ) as outfile:
        outfile.seek(os.stat('NessusDB.json').st_size - 1)
        outfile.write( ',{}'.format(json.dumps(api_results, indent=4)[1:]))

def main():


# Setup the command line arguments
    parser = argparse.ArgumentParser(description='Search Shodan and get the CVEs, POCs and Solutions')
    parser.add_argument('-q', '--query', help='Search Shodan using a query')
    parser.add_argument('-l', '--limit', type=int, help='Limit the number of results')
    parser.add_argument('-o', '--output',  help='Output file')
    parser.add_argument('-i', '--input', help='input file')
    parser.add_argument('-H', '--host', help='Search Shodan using a host')
    parser.add_argument('-u', '--update', help='Hostname of Nessus API', default='https://localhost:8834')
    parser.add_argument('-k', '--key', help='Shodan API Key')
    parser.add_argument('-x', '--history', help='Search Historical Data for Host (True/False)')
    parser.add_argument('-a', '--access', help='Nessus Access Key')
    parser.add_argument('-s', '--secret', help='Nessus Secret Key')


    args = parser.parse_args()

    # Setup the API key
    API_KEY = get_api_key()


    # Check if the user is searching by query
    if args.query:
        # check if Nessus Database exists
        DATA = nessusCheck()
        search_query(DATA, args.query, API_KEY, args.limit, args.output)
    elif args.host:
        # check if Nessus Database exists
        DATA = nessusCheck()
        search_host(DATA, args.host, API_KEY, args.output, args.history)
    elif args.input:
        # check if Nessus Database exists
        DATA = nessusCheck()
        search_file(DATA, args.input, API_KEY, args.output, args.history)
    elif args.update:
        asyncio.run(nessus_api_update_run( args.access, args.secret, args.update))
    else:
        parser.print_help()

    
# Run the main function
if __name__ == '__main__':
        main()