#import dnspython packages
import string
from typing import List
from urllib import response
import dns.resolver
import dns.name
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query
import time
import datetime
import sys

# Initializing Root Server List
rootServerList = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
]

# Recursive Function to generate DNS queries
def recursive_query_resolver(searchDomain, queryType, targetServer, depth, maxDepth):
    # Building the Search string for this iteration
    domainNameArray = searchDomain.split(".")
    searchText = ""
    k=0
    for i in range(len(domainNameArray)-depth,len(domainNameArray)):
        if k==0:
            searchText = domainNameArray[i]
            k+=1
        else:
            searchText += "." + domainNameArray[i]
    
    # Configuring  the DNS request
    qname = dns.name.from_text(searchText)
    q = dns.message.make_query(qname, dns.rdatatype.A)

    # Making the DNS request using UDP and handling exception for timeout
    try:
        response = dns.query.udp(q, targetServer, 5)
    except dns.exception.Timeout:
        return None

    # Check if Answer Section is present in response and max depth is reached
    if depth == maxDepth and len(response.answer) != 0:
        return response.answer
    # If Answer section not present access Additional section
    else:
        # If Additional section not present access Authority section
        if len(response.additional) == 0:
            # If Authority section not present return current targetserver as next targetserver
            if len(response.authority) == 0:
                targetServerList = [targetServer]
            # Acccess Authority Section
            else:
                # Handling scenario for NS record in Authority section
                if response.authority[0].rdtype == 2:
                    nameServerList = []
                    for item in response.authority[0].items:
                        nameServerList.append(item.to_text())
                    # Call my_dig to resolve name server
                    targetServerList = my_dig(nameServerList[0], "A", False)
                # Handling scenario for SOA record in Authority section
                elif response.authority[0].rdtype == 6:
                    targetServerList = [targetServer]
        # If additional section  present parse it for IP Address of name server
        else:
            targetServerList=[]
            for record in response.additional:
                if record.rdtype == 1:
                    for item in record.items:
                        targetServerList.append(item.address)
    
    # Increasing the depth counter by one
    depth+=1

    # Handling scenario when max depth of tree reached
    if depth > maxDepth:
        # Configuring  the DNS request
        qname = dns.name.from_text(searchDomain)
        q = dns.message.make_query(qname, queryType)
        # Making the DNS request using UDP 
        response = dns.query.udp(q, targetServerList[0], 5)
        return response.answer
    # Handling scenario when max depth of tree not reached
    else:
        # Loop through the list of available name servers
        j=0
        while j<len(targetServerList):
            # Recursively call recursive_query_resolver to resolve the domain name for the next level
            response = recursive_query_resolver(searchDomain, queryType, targetServerList[j], depth, maxDepth)
            # Handling scenario for Name server timeout
            if response == None:
                print("Name Server timeout occured")
                # quit() # Uncomment this line to stop looping
                print("Moving to next available name server")
                j+=1
            else:
                return response
        # Handling scenario where all Name servers unreachable
        print("DNS encountered an error while parsing")
        quit()


# Mydig Tool implmentation
def my_dig(domainName, resolutionType, mainCall):
    # Checking whether correct type is provided
    while(1): 
        if resolutionType=="A" or resolutionType=="NS" or resolutionType=="MX":
            break
        else:
            resolutionType = input("Please enter correct type of DNS resolution -> A, NS or MX\n")
            continue

    # Splitting up the domain name using split function on basis of "."
    domainNameArray = domainName.split(".")
    # Calculate maximum depth of recursion tree
    maxDepth = len(domainNameArray)

    # Looping through available root servers in case of failure
    j=0
    resolution = False
    while j<len(rootServerList):
        # Calling recursive_query_resolver function to resolve DNS query by supplying initial depth as 1
        response = recursive_query_resolver(domainName, resolutionType, rootServerList[j], 1, maxDepth) 
        # Handling scenario where root server timeout occurs
        if response == None:
            print("Root server timeout occured")
            print("Moving to next available root server")
            j+=1
        else:
            # Parsing for IP if called from some other method than main method
            if mainCall == False:
                # Extract Target Server List from response and send it back
                targetServerList=[]
                for record in response:
                    if record.rdtype == 1:
                        for item in record.items:
                            targetServerList.append(item.address)
                return targetServerList
            # Handling scenario where my_dig called from main method
            else:
                # Handling CNAME resolution 
                if response[0].rdtype == 5 and resolutionType=="A":
                    return my_dig(response[0][0].to_text(), "A", True)
                elif response[0].rdtype == 5 and resolutionType=="MX":
                    return my_dig(response[0][0].to_text(), "A", True)
                else:
                    return response
    # Handling scenario where all Root servers unreachable
    if resolution == False:
        print("Unable to reach any available Root servers")

# Main function
if __name__ == "__main__":

    # Taking Input of domain name and type of DNS resolution
    domainName = input("Enter the name of the domain you want to resolve\n")
    resolutionType = input("Enter type of DNS resolution -> A, NS or MX\n")

    # Initializing Start Time
    start_time = time.time()

    # Calling mydig tool
    result = my_dig(domainName, resolutionType, True)

    # Calculating Final Time
    total_time = time.time() - start_time

    # Printing Output
    print("\nQUESTION SECTION: \n")
    print("{}   IN  {}".format(domainName, resolutionType))
    print("\nANSWER SECTION: \n")
    for item in result:
        for i in item:
            address = i.to_text()
    print("{} IN {}  {}".format(domainName, resolutionType, address))
    print("\nQuery Time: {} msec".format(round(total_time*1000,4)))
    print("\nWHEN: {}".format(datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y\n")))
    print("MSG SIZE rcvd: {}".format(str(sys.getsizeof(result))))