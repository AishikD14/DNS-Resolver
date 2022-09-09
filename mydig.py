#import dnspython packages
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

# A = dns.resolver.resolve('stackoverflow.com', 'A')
# print(A.response.answer[0][0].address)

# qname = dns.name.from_text("com")
# q = dns.message.make_query(qname, dns.rdatatype.NS)
# print("")

# r = dns.query.udp(q, "8.8.8.8",3)
# print(r)

# print("")
# print("The nameservers are:")
# ns_rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS)
# for rr in ns_rrset:
#     print(rr.target)
# print("")
# print("")
# quit()

# Mydig Tool implmentation
print("Mydig Tool Started.")

# Taking Input of domain name and type of DNS resolution
domainName = input("Enter the name of the domain you want to resolve\n")
resolutionType = input("Enter type of DNS resolution -> A, NS or MX\n")
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
        # Looping thorugh Root Server List in case of failure
        j=0
        while j<len(rootServerList):
            try:
                # Configuring up the DNS request
                qname = dns.name.from_text(searchDomain)
                q = dns.message.make_query(qname, dns.rdatatype.NS)
                # Making the DNS request using UDP to the root server
                r = dns.query.udp(q, rootServerList[j],5)
                # Parsing thorugh Resource Record to get IP Addresses of name server
                targetServerList=[]
                for record in r.additional:
                    for item in record.items:
                        targetServerList.append(item.address)
                print("The address of Name Server of {} is: {}".format(searchDomain, targetServerList[0]))
                break
            # Handling situation where root server doesn't answer
            except dns.exception.Timeout:
                print("Root not answering, moving to next available root server")
                j=j+1
    # code for hitting the name servers except root 2nd iteration onwards
    else:
        # Building the domain string to be searched in this iteration
        searchDomain = domainNameArray[i] + "." + searchDomain
        # Looping thorugh Target Name Server List in case of failure
        j=0
        while j<len(targetServerList):
            try:
                # Configuring up the DNS request
                qname = dns.name.from_text(searchDomain)
                q = dns.message.make_query(qname, dns.rdatatype.NS)
                # Making the DNS request using UDP to the name servers
                r = dns.query.udp(q, targetServerList[j],5)
                # print(r)
                # Parsing thorugh Resource Record to get IP Addresses of name server
                targetServerList=[]
                for record in r.additional:
                    for item in record.items:
                        targetServerList.append(item.address)
                if len(targetServerList) != 0:
                    print("The address of Name Server of {} is: {}".format(searchDomain, targetServerList[0]))
                else:
                    print("Additional processing required")
                break
            # Handling situation where name server doesnt answer
            except dns.exception.Timeout:
                print("Name server not answering, moving to next available name server")
                j=j+1
    i-=1

# Ask Authoratitive Name server for A record of searched domain name
qname = dns.name.from_text(domainName)
q = dns.message.make_query(qname, dns.rdatatype.A)
# Making the DNS query using UDP to the Authoratitive name server for the searched domain name
r = dns.query.udp(q, targetServerList[0],5)
print(r.answer)

# Validating against Ground Truth using Stub resolver
A = dns.resolver.resolve(domainName, 'A')
print("Ground truth is: ")
print(A.response.answer)

# print("Answer for {} with type {} is nm".format(domainName, resolutionType))