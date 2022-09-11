#import dnspython packages
import string
from typing import List
import dns.resolver
import dns.name
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query

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

# print("The nameservers are:")
# ns_rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS)
# for rr in ns_rrset:
#     print(rr.target)

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
    
    print("Searching for {} from {}".format(searchText, searchDomain))
    # Configuring  the DNS request
    qname = dns.name.from_text(searchText)
    q = dns.message.make_query(qname, queryType)

    # Making the DNS request using UDP and handling exception for timeout
    try:
        response = dns.query.udp(q, targetServer, 5)
    except dns.exception.Timeout:
        return None

    # Check if Additional Section is present in response
    # If additional section not present access Authority section
    if len(response.additional) == 0:
        print("Additional Absent, Accessing authority")
        if response.authority[0].rdtype == 2:
            # Handling scenario for NS record in Authority section
            print("NS record present")
            nameServerList = []
            for item in response.authority[0].items:
                nameServerList.append(item.to_text())
            print("Name servers for {} are {}".format(searchText, nameServerList))
            targetServerList = my_dig(nameServerList[0], "NS", False)
        elif response.authority[0].rdtype == 6:
            # Handling scenario for SOA record in Authority section
            print("SOA record present")
            print("Target server is {}".format(targetServer))
            targetServerList = [targetServer]
    # If additional section  present parse it for IP Address of name server
    else:
        targetServerList=[]
        for record in response.additional:
            if record.rdtype == 1:
                for item in record.items:
                    targetServerList.append(item.address)
    
    print("Iteration {} complete for {}".format(depth, searchText))
    print(targetServerList)

    # Handling scenario for SOA record in Additional section
    if len(targetServerList) == 0:
        print("Additional Parsing required for SOA record")
        quit()
    
    # Increasing the depth counter by one
    depth+=1

    # Handling scenario when max depth of tree reached
    if depth > maxDepth:
        print("Depth reached")
        qname = dns.name.from_text(searchDomain)
        q = dns.message.make_query(qname, dns.rdatatype.A)
        # Making the DNS request using UDP 
        response = dns.query.udp(q, targetServerList[0], 5)
        # print(response)
        # quit()
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
        # Calling recursive_query_resolver function to resolve DNS query by supplying initial depth as 1
        response = recursive_query_resolver(domainName, dns.rdatatype.NS, rootServerList[j], 1, maxDepth) 
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
                print("Printing final response")
                print("Answer for {} with type {} is {}".format(domainName, resolutionType, response))
                resolution = True
                break
    if resolution == False:
        print("Unable to reach any available Root servers")

#Validating against Ground Truth using Stub resolver
def ground_truth(domainName, resolutionType): 
    print("---------------")
    A = dns.resolver.resolve(domainName, resolutionType)
    print("Ground truth is: ")
    print(A.response.answer)
    # print(A.response.answer[0][0].address)

# Main function
if __name__ == "__main__":
    print("Mydig Tool Started.")

    # Taking Input of domain name and type of DNS resolution
    # domainName = input("Enter the name of the domain you want to resolve\n")
    # resolutionType = input("Enter type of DNS resolution -> A, NS or MX\n")
    # domainName = "amazon.com" # working
    # domainName = "google.com" # working
    # domainName = "cnn.com"    # working
    # domainName = "google.co.jp" # working
    domainName = "aws.amazon.com"
    resolutionType = "A"
    print("Performing DNS query for {}".format(domainName))

    # Calling mydig tool
    my_dig(domainName, resolutionType, True)
    ground_truth(domainName, resolutionType)