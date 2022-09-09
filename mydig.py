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

# Function to generate DNS queries
def query_resolver(searchDomain, queryType, serverList):
    j=0
    while j<len(serverList):
        try:
            # Configuring  the DNS request
            qname = dns.name.from_text(searchDomain)
            q = dns.message.make_query(qname, queryType)
            # Making the DNS request using UDP 
            r = dns.query.udp(q, serverList[j],5)
            return r
        except dns.exception.Timeout:
            print("Name server timeout occured, moving to next available name server")
            j=j+1
    # return None
    print("Unable to reach any available name servers")
    quit()

# Mydig Tool implmentation
def my_dig():
    print("Mydig Tool Started.")

    # Taking Input of domain name and type of DNS resolution
    # domainName = input("Enter the name of the domain you want to resolve\n")
    # resolutionType = input("Enter type of DNS resolution -> A, NS or MX\n")
    domainName = "cnn.com"
    resolutionType = "A"

    # Checking whether correct type is provided
    while(1): 
        if resolutionType=="A" or resolutionType=="NS" or resolutionType=="MX":
            break
        else:
            resolutionType = input("Please enter correct type of DNS resolution -> A, NS or MX\n")
            continue

    # Splitting up the domain name using split function on basis of "."
    domainNameArray = domainName.split(".")

    # Start of iterative DNS query
    i=len(domainNameArray)-1
    while i>=0:
        # Code for hitting root server the first time
        if i==len(domainNameArray)-1:
            # Retrieving the top level domain name for searching inside root
            searchDomain = domainNameArray[i]
            # Calling query_resolver method to make the DNS request
            response = query_resolver(searchDomain, dns.rdatatype.NS, rootServerList) 

            # Parsing thorugh Resource Record to get IP Addresses of name server
            targetServerList=[]
            for record in response.additional:
                for item in record.items:
                    targetServerList.append(item.address)
            print("Root server returned the address of Name Server of {} is: {}".format(searchDomain, targetServerList[0]))
                
        # code for hitting the name servers except root 2nd iteration onwards
        else:
            # Building the domain string to be searched in this iteration
            searchDomain = domainNameArray[i] + "." + searchDomain
            # Calling query_resolver method to make the DNS request
            response = query_resolver(searchDomain, dns.rdatatype.NS, targetServerList)
            
            # Parsing thorugh Resource Record to get IP Addresses of name server
            targetServerList=[]
            for record in response.additional:
                for item in record.items:
                    targetServerList.append(item.address)
            if len(targetServerList) != 0:
                print("The address of Name Server of {} is: {}".format(searchDomain, targetServerList[0]))
            else:
                print("Additional processing required")
        i-=1

    # Ask Authoratitive Name server for A record of searched domain name
    # Calling query_resolver method to make the DNS request
    response = query_resolver(domainName, dns.rdatatype.A, targetServerList)

    # Parsing the response to check whether A record or Cname record returned
    for record in response.answer:
        if record.rdtype == 5:
            print("Record is a Cname, iterating further")
            for item in record.items:
                print(item)
                qname = dns.name.from_text(item.to_text())
                q = dns.message.make_query(qname, dns.rdatatype.A)
                # Making the DNS query using UDP to the Authoratitive name server for the Cname
                print("Target server used for A record: ",targetServerList[0])
                r = dns.query.udp(q, targetServerList[0],5)
                print(r)
        elif record.rdtype == 1:
            print("Record is a A")
            for item in record.items:
                print(item)
        else:
            print("New Record type found: ", record.rdtype)

#Validating against Ground Truth using Stub resolver
def ground_truth(): 
    print("---------------")
    A = dns.resolver.resolve("cnn.com", 'A')
    print("Ground truth is: ")
    print(A.response.answer)
    # print(A.response.answer[0][0].address)

# print("Answer for {} with type {} is nm".format(domainName, resolutionType))

if __name__ == "__main__":
    my_dig()
    ground_truth()