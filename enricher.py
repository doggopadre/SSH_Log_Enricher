import requests
import os
import mysql.connector
import re
import itertools
from collections import Counter
from termcolor import colored



#Variables for extracting failed IPv4 from logs
search_string = 'failed password'
suspicious_ips = []
ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'


#Parsing SSH log data
with open('ssh_logs.log', 'r') as file:
    
    for line in file:
        
        if search_string in line.lower():
            match_ip = re.findall(ipv4_pattern, line)
            suspicious_ips.append(match_ip)

#flatten the list to remove inner lists
flatten_list = list(itertools.chain.from_iterable(suspicious_ips))
attempt_count = Counter(flatten_list)


'''
finding IPs with more than 5 filed login attemps
We can even split the log by space character to get the time, 
and do contitional based on number of attempts logged under say 1 minute
and also get the user for which they failed
'''


ips_to_enrich = list(filter(lambda x: attempt_count[x] >= 5, attempt_count))
        
print(
     colored(
         "[++] Done collecting Failed Logins from SSH Logs.....\n\n"
         ), 'green'
     )
 
 
print(
     colored(
         "[++] Starting IPV4 enrichmentm with VirusTotal....."
         ), 'blue'
     )
#Now lets ernich the IPs with VirusTotal
#variables for VirusTotal enrichment

total_list = []
key = os.environ.get("VT_KEY") #make sure you have this exported
url = "https://www.virustotal.com/api/v3/ip_addresses/"
headers = {
    'x-apikey': f'{key}'
}

for ip in ips_to_enrich:
    
    response = requests.get(url + ip, headers=headers)
    data = response.json()
    
    


#     #with open('VirusTotalResult.json', 'r') as file:

    ip = data['data']['id']
    as_owner = data['data']['attributes']['as_owner']
    enrichment_results = data['data']['attributes']['last_analysis_results']
   

    for value in enrichment_results.values():
        
        if 'malicious' in value['category'] or 'suspicious' in value['category']:
            
            malicous_ips = {} #If you put this dict outside the for loop, it'll only append with last entry
            
            malicous_ips['IP Address'] = data['data']['id']
            malicous_ips["AS Owner"] = data['data']['attributes']['as_owner']
            malicous_ips['Scan Engine'] = value['engine_name']
            malicous_ips["Category"] = value['category']
            
            total_list.append(malicous_ips)
            print(f"{malicous_ips['Scan Engine']} found {malicous_ips['IP Address']} as {malicous_ips['Category']} \n")

print(
     colored(
         "[++] Done Enriching....."
         ), 'green'
     )

# print(total_list)


#Cobnect to mysql database

db = mysql.connector.connect(
    user = 'root',
    password = '',
    host= 'localhost',
    database = 'VirusTotalEnrichments'
)

# # #Create cursor to start executing queries
my_cursor = db.cursor()

#Checking the table-column details
# my_cursor.execute('DESCRIBE Malicios_IPs')
# for cursor in my_cursor:
#     print(cursor)


#entering items from the list into the table
for entry in total_list:
    query = 'INSERT INTO Malicios_IPs (ip_address, as_owner, scan_engine, category) VALUES (%s, %s, %s, %s)'
    values = (entry['IP Address'], entry['AS Owner'], entry['Scan Engine'], entry['Category'])
    
    my_cursor.execute(query, values)
    db.commit()




