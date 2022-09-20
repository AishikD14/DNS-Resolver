#import dnspython packages
from typing import List
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

# Initialize Root Signing Keys to verify autenticity of Root
root_signing_key = ["19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5", "20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d"]

# Method for fetching DNSKEY records
def fetch_dnskey(searchText, targetServerList):
    # Configuring  the DNS request
    qname = dns.name.from_text(searchText)
    q = dns.message.make_query(qname, dns.rdatatype.DNSKEY, want_dnssec = True)

    # Looping through list of available target servers
    index = 0
    KSK = None
    ZSK = None
    RRSIG = None
    RRSET = None
    
    while index<len(targetServerList):
        try:
            # Making the DNS request using UDP
            response = dns.query.udp(q, targetServerList[index], 5)

            # Parse the answer section for getting RRSIG, RRSET, KSK & ZSK
            for record in response.answer:
                if record.rdtype == 48:
                    RRSET = record
                    for item in record:
                        if item.flags == 257:
                            KSK = item
                        elif item.flags == 256:
                            ZSK = item
                elif record.rdtype == 46:
                    RRSIG = record
            return RRSIG, ZSK, KSK, RRSET
        except dns.exception.Timeout:
            index+=1
    return None, None, None, None

# Method for verifying KSK value
def verify_KSK(searchDomain, KSK, DS):
    # PArsing the DS record
    for item in DS:
        ds = item
    # Hashing the KSK
    hash = dns.dnssec.make_ds(dns.name.from_text(searchDomain), KSK, 'sha256')

    # Comparing KSK with hash value
    if str(ds) == str(hash):
        return True
    else:
        return False

# Method for verifying DNSKEY value
def verify_DNSKEY(RRSET, RRSIG, searchText):
    try:
        dns.dnssec.validate(RRSET, RRSIG, {dns.name.from_text(searchText): RRSET})
    except dns.dnssec.ValidationFailure:
        print("DNSSec verification failed")
        quit()

# Recursive Function to generate DNS queries
def recursive_query_resolver(searchDomain, queryType, targetServer, depth, maxDepth):
    # Building the Search string for this iteration
    domainNameArray = searchDomain.split(".")
    # Get rid of blank space from domain array
    if domainNameArray[len(domainNameArray)-1] == "":
        domainNameArray = domainNameArray[:len(domainNameArray)-1]
    
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
    q = dns.message.make_query(qname, dns.rdatatype.DNSKEY, want_dnssec = True)

    # Making the DNS request using UDP and handling exception for timeout
    try:
        response = dns.query.udp(q, targetServer, 5)
    except dns.exception.Timeout:
        return None
    
    # Check if not root
    if searchText != "":
        # Check Authority Section for DS record to verify whether DNSSEC supported or not
        supported = False
        for record in response.authority:
            # Seach for DS record
            if record.rdtype == 43:
                supported = True
                DS = record
        # If DNSSEC not supported end program
        if supported == False:
            print("DNSSEC not supported")
            quit()

        # PArse Authority section to get RRSET and RRSIG data
        for record in response.authority:
            if record.rdtype == 2:
                RRSET1 = record
            elif record.rdtype == 46:
                RRSIG1 = record

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
                    # Call my_dnssec to resolve name server
                    targetServerList = my_dnssec(nameServerList[0], "A", False)
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
            
            # Check if not root
            if searchText != "":
                # Fetch DNSKEY records
                RRSIG2, ZSK, KSK, RRSET2 = fetch_dnskey(searchText, targetServerList)

                # Handling scenario if DNSKEY records not present
                if RRSIG2 == None or ZSK == None or KSK == None or RRSET2 == None:
                    print("DNSSEC not supported")
                    quit()

                # Verify KSK value
                verificationStatus = verify_KSK(searchText, KSK, DS)
                # If KSK verification successful
                if verificationStatus == True:
                    # Verify DNSKEY value
                    verify_DNSKEY(RRSET2, RRSIG2, searchText)
                # If KSK verification failed
                else:
                    print("DNSSec verification failed")
                    quit()
            
    # Increasing the depth counter by one
    depth+=1

    # Handling scenario when max depth of tree reached
    if depth > maxDepth:
        # Configuring  the DNS request
        qname = dns.name.from_text(searchDomain)
        q = dns.message.make_query(qname, dns.rdatatype.A)
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

# Mydnssec Tool implmentation
def my_dnssec(domainName, resolutionType, mainCall):
    # Splitting up the domain name using split function on basis of "."
    domainNameArray = domainName.split(".")
    # Calculate maximum depth of recursion tree
    maxDepth = len(domainNameArray)

    # Looping through available root servers in case of failure
    j=0
    resolution = False
    while j<len(rootServerList):
        # Verify Root Signature

        # Fetching Root DNSKEY
        RRSIG2, ZSK, KSK, RRSET2 = fetch_dnskey(".", [rootServerList[j]])

        # Hashing the KSK Value
        hash = dns.dnssec.make_ds(dns.name.from_text("."), KSK, 'sha256')

        # Compare Root signing key with hashed KSK
        verification = False
        for i in root_signing_key:
            if str(hash) == i:
                verification = True
                break
        # Handling scenario where root server verification fails
        if verification == False:
            print("DNSSec Verification Failed")
            quit()
            
        # Calling recursive_query_resolver function to resolve DNS query by supplying initial depth as 1
        response = recursive_query_resolver(domainName, dns.rdatatype.DNSKEY, rootServerList[j], 1, maxDepth) 
        # Handling scenario where root server timeout occurs
        if response == None:
            print("Root server timeout occured")
            print("Moving to next available root server")
            j+=1
        else:
            # Parsing for IP if called from someplace other than main method
            if mainCall == False:
                # Extract Target Server List from response and send it back
                targetServerList=[]
                for record in response:
                    if record.rdtype == 1:
                        for item in record.items:
                            targetServerList.append(item.address)
                return targetServerList
            # Handling scenario where my_dnssec called from main method
            else:
                # Handling CNAME resolution 
                if response[0].rdtype == 5 and resolutionType=="A":
                    return my_dnssec(response[0][0].to_text(), "A", True)
                elif response[0].rdtype == 5 and resolutionType=="MX":
                    return my_dnssec(response[0][0].to_text(), "A", True)
                else:
                    return response
    # Handling scenario where all Root servers unreachable
    if resolution == False:
        print("Unable to reach any available Root servers")

# Main function
if __name__ == "__main__":
    # Taking Input of domain name for DNS resolution
    domainName = input("Enter the name of the domain you want to resolve\n")
    resolutionType = "A"

    # Initializing Start Time
    start_time = time.time()

    # Calling my_dnssec tool
    result = my_dnssec(domainName, resolutionType, True)

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