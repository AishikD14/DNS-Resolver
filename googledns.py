#import dnspython packages
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
import os

# Main function
if __name__ == "__main__":

    website_list = ["youtube.com", "en.wikipedia.org", "twitter.com", "instagram.com", "amazon.com"]
    writeData = []
    for i in website_list:
        timeArray = []
        for j in range(10):
            start_time = time.time()
            # os.system("nslookup "+i)
            dns.resolver.override_system_resolver(resolver="8.8.8.8")
            A = dns.resolver.resolve(i, "A")
            dns.resolver.restore_system_resolver()
            total_time = time.time() - start_time
            timeArray.append(round(total_time*1000,4))
        mean = sum(timeArray)/10
        writeData.append([i, mean])
    with open("part2.csv", "w") as f:
        for i in writeData:
            f.write("%s-%s\n" % (i[0], i[1]))