import numpy as np
import matplotlib.pyplot as plt

f = open("part1.csv", "r")
part1=[]
for x in f:
    # print(x)
    part1.append(float(x.split("-")[1].strip("\n")))
# print(part1)

f = open("part2.csv", "r")
part2=[]
for x in f:
    # print(x)
    part2.append(float(x.split("-")[1].strip("\n")))
# print(part2)

f = open("part3.csv", "r")
part3=[]
for x in f:
    # print(x)
    part3.append(float(x.split("-")[1].strip("\n")))
# print(part3)


# set width of bar
barWidth = 0.25
fig = plt.subplots(figsize =(12, 8))
 
# Set position of bar on X axis
br1 = np.arange(len(part1))
br2 = [x + barWidth for x in br1]
br3 = [x + barWidth for x in br2]
 
# Make the plot
plt.bar(br1, part1, color ='r', width = barWidth,
        edgecolor ='grey', label ='MyDig Resolver')
plt.bar(br2, part2, color ='g', width = barWidth,
        edgecolor ='grey', label ='Google DNS (8.8.8.8)')
plt.bar(br3, part3, color ='b', width = barWidth,
        edgecolor ='grey', label ='Local DNS (192.168.214.243)')
 
# Adding Xticks
plt.xlabel('Website Name', fontweight ='bold', fontsize = 15)
plt.ylabel('Average Resolution Time (msec)', fontweight ='bold', fontsize = 15)
plt.xticks([r + barWidth for r in range(len(part1))],
        ['youtube.com', 'en.wikipedia.org', 'twitter.com', 'instagram.com', 'amazon.com'])

plt.title("DNS Resolution Time", fontweight ='bold')
 
plt.legend()
plt.show()