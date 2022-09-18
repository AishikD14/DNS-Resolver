#import dnspython packages
import string
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

# Initializing Root Server Dict
rootServerDict = {
    "a.root-servers.net": "198.41.0.4",
    "b.root-servers.net": "199.9.14.201",
    "c.root-servers.net": "192.33.4.12",
    "d.root-servers.net": "199.7.91.13",
    "e.root-servers.net": "192.203.230.10",
    "f.root-servers.net": "192.5.5.241",
    "g.root-servers.net": "192.112.36.4",
    "h.root-servers.net": "198.97.190.53",
    "i.root-servers.net": "192.36.148.17",
    "j.root-servers.net": "192.58.128.30",
    "k.root-servers.net": "193.0.14.129",
    "l.root-servers.net": "199.7.83.42",
    "m.root-servers.net": "202.12.27.33",
}

# Root Signing Keys
# root_signing_key = ["19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5", "20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d"]

def fetch_dnskey(searchText, targetServerList):
    qname = dns.name.from_text(searchText)
    q = dns.message.make_query(qname, dns.rdatatype.DNSKEY, want_dnssec = True)
    index = 0
    KSK = None
    ZSK = None
    RRSIG = None
    RRSET = None
    while index<len(targetServerList):
        try:
            response = dns.query.udp(q, targetServerList[index], 5)
            # print(response)
            for record in response.answer:
                if record.rdtype == 48:
                    # print("------------------------")
                    # print("RRSET2")
                    RRSET = record
                    # print(record)
                    for item in record:
                        if item.flags == 257:
                            # print("------------------------")
                            # print("Public KSK")
                            KSK = item
                            # print(item)
                        elif item.flags == 256:
                            # print("------------------------")
                            # print("Public ZSK")
                            ZSK = item
                            # print(item)
                elif record.rdtype == 46:
                    # print("------------------------")
                    # print("RRSIG2")
                    RRSIG = record
                    # print(record)
            return RRSIG, ZSK, KSK, RRSET
        except dns.exception.Timeout:
            index+=1
    return None, None, None, None

def verify_KSK(searchDomain, KSK, DS):
    hash = dns.dnssec.make_ds(dns.name.from_text(searchDomain), KSK, 'sha256')
    if DS == hash:
        return True
    else:
        return False

def verify_ZSK(RRSET, RRSIG, searchText):
    try:
        dns.dnssec.validate(RRSET, RRSIG, {dns.name.from_text(searchText): RRSET})
    except dns.dnssec.ValidationFailure:
        print("DNSSec verification failed")
        quit()

def verify_rrset(RRSET, RRSIG, searchText, ZSK):
    try:
        dns.dnssec.validate(RRSET, RRSIG, {dns.name.from_text(searchText): ZSK})
        # dns.dnssec.validate_rrsig(RRSET, RRSIG, {dns.name.from_text(searchText): RRSET})
    except dns.dnssec.ValidationFailure:
        print("DNSSec verification failed for verify rrset")
        quit()

# Recursive Function to generate DNS queries
def recursive_query_resolver(searchDomain, queryType, targetServer, depth, maxDepth):
    # Building the Search string for this iteration
    # print(searchDomain)
    domainNameArray = searchDomain.split(".")
    if domainNameArray[len(domainNameArray)-1] == "":
        domainNameArray = domainNameArray[:len(domainNameArray)-1]
    # print(len(domainNameArray))
    # quit()
    searchText = ""
    k=0
    for i in range(len(domainNameArray)-depth,len(domainNameArray)):
        if k==0:
            searchText = domainNameArray[i]
            k+=1
        else:
            searchText += "." + domainNameArray[i]
    
    print("Searching for {} from {}".format(searchText, searchDomain))

    # Configuring  the DNS request
    qname = dns.name.from_text(searchText)
    q = dns.message.make_query(qname, dns.rdatatype.DNSKEY, want_dnssec = True)

    # Making the DNS request using UDP and handling exception for timeout
    try:
        response = dns.query.udp(q, targetServer, 5)
    except dns.exception.Timeout:
        return None

    # print("^^^^^^^^^^^^^^^")
    # print(response)
    
    if searchText != "":
        # Check Authority Section for DS record to verify whether DNSSEC supported or not
        supported = False
        for record in response.authority:
            if record.rdtype == 43:
                supported = True
                for item in record:
                    # print("------------------------")
                    DS =item
                    # print("DS")
                    # print(item)
                break
        # If DNSSEC not supported end program
        if supported == False:
            print("DNSSEC not supported")
            quit()

        for record in response.authority:
            if record.rdtype == 2:
                # print("------------------------")
                RRSET1 = record
                # print("RRSET1")
                # print(record)
            elif record.rdtype == 46:
                # print("------------------------")
                RRSIG1 = record
                # print("RRSIG1")
                # print(record)

    # Check if Additional Section is present in response
    # If additional section not present access Authority section
    if depth == maxDepth and len(response.answer) != 0:
        # Fetch KSK, ZSK and RRSIG to validate authenticity
        # qname = dns.name.from_text(searchText)
        # q = dns.message.make_query(qname, dns.rdatatype.DNSKEY, want_dnssec = True)
        return response.answer
    else:
        if len(response.additional) == 0:
            # print("Additional Absent, Accessing authority")
            if len(response.authority) == 0:
                targetServerList = [targetServer]
            else:
                if response.authority[0].rdtype == 2:
                    # Handling scenario for NS record in Authority section
                    nameServerList = []
                    for item in response.authority[0].items:
                        nameServerList.append(item.to_text())
                    targetServerList = my_dig(nameServerList[0], "A", False)
                elif response.authority[0].rdtype == 6:
                    # Handling scenario for SOA record in Authority section
                    targetServerList = [targetServer]
        # If additional section  present parse it for IP Address of name server
        else:
            targetServerList=[]
            for record in response.additional:
                if record.rdtype == 1:
                    for item in record.items:
                        targetServerList.append(item.address)

            if searchText != "":
                # Fetch KSK & ZSK
                RRSIG2, ZSK, KSK, RRSET2 = fetch_dnskey(searchText, targetServerList)

                if RRSIG2 == None or ZSK == None or KSK == None or RRSET2 == None:
                    print("DNSSEC not supported")
                    quit()

                verificationStatus = verify_KSK(searchText, KSK, DS)
                if verificationStatus == True:
                    print("KSK Verified")
                    verify_ZSK(RRSET2, RRSIG2, searchText)
                    print("ZSK Verified")
                    # verify_rrset(RRSET1, RRSIG1, searchText, ZSK)
                    # print("Verification successful")
                    # quit()
                else:
                    print("DNSSec verification failed for KSK")
                    quit()
            

    
    # Increasing the depth counter by one
    depth+=1

    # Handling scenario when max depth of tree reached
    if depth > maxDepth:
        # print("Depth reached")
        qname = dns.name.from_text(searchDomain)
        q = dns.message.make_query(qname, dns.rdatatype.A)
        # Making the DNS request using UDP 
        response = dns.query.udp(q, targetServerList[0], 5)
        # print("^^^^^^^^^^^")
        # print(response)
        return response.answer
    # Handling scenario when max depth of tree not reached
    else:
        j=0
        while j<len(targetServerList):
            response = recursive_query_resolver(searchDomain, queryType, targetServerList[j], depth, maxDepth)
            if response == None:
                print("Name Server timeout occured")
                quit() # Remove this line to continue recursion
                print("Moving to next available name server")
                j+=1
            else:
                return response
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
        # # Verify Root Signature
        # q = dns.message.make_query(".", dns.rdatatype.DNSKEY, want_dnssec = True)
        # secResponse = dns.query.tcp(q, rootServerList[j], 5)
        # print(secResponse)
        # if len(secResponse) != 0:
            
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
                targetServerList=[]
                for record in response:
                    if record.rdtype == 1:
                        for item in record.items:
                            targetServerList.append(item.address)
                return targetServerList
            else:
                if response[0].rdtype == 5 and resolutionType=="A":
                    return my_dig(response[0][0].to_text(), "A", True)
                elif response[0].rdtype == 5 and resolutionType=="MX":
                    return my_dig(response[0][0].to_text(), "A", True)
                else:
                    # print("Printing final response")
                    # print("Answer for {} with type {} is {}".format(domainName, resolutionType, response))
                    return response
    if resolution == False:
        print("Unable to reach any available Root servers")

#Validating against Ground Truth using Stub resolver
def ground_truth(domainName, resolutionType): 
    print("---------------")
    A = dns.resolver.resolve(domainName, resolutionType)
    print("Ground truth is: ")
    print(A.response.answer)

# Main function
if __name__ == "__main__":
    # print("Mydig Tool Started.")

    # Taking Input of domain name and type of DNS resolution
    domainName = input("Enter the name of the domain you want to resolve\n")
    # resolutionType = input("Enter type of DNS resolution -> A, NS or MX\n")
    # domainName = "amazon.com" # working
    # domainName = "google.com" # working
    # domainName = "www.cnn.com"    # working
    # domainName = "google.co.jp" # working
    # domainName = "aws.amazon.com"
    # domainName = "aishikdeb.com"
    # domainName = "verisigninc.com"
    # domainName = "dnssec-failed.org"
    resolutionType = "A"
    # print("Performing DNS query for {}".format(domainName))

    # Calling mydig tool
    start_time = time.time()
    result = my_dig(domainName, resolutionType, True)
    total_time = time.time() - start_time
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
    # ground_truth(domainName, resolutionType)