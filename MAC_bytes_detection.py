#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Attempt to detect the MAC addresses revealerd after sniffing in monitor mode. 
# MACs are added in a dictionary that has MACs themselves as key and two values 
# for each MAC, repsectively: [uplink bytes, downlink bytes].

import pyshark
import numpy as np
import matplotlib.pyplot as plt
import matplotlib


""" This function attach a text label above each bar in *rects*, displaying its height. """
def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        ax.annotate('{}'.format(height),
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')


""" Starting the program """

# Opening capute file:
cap = pyshark.FileCapture('/Users/lucaferraro/Desktop/PoliMi/First_year/Wireless_networks/Wirelesss_internet/Project/MAC_count2.pcapng', 'r')#cap = pyshark.FileCapture('/Users/lucaferraro/Desktop/PoliMi/First_year/Wireless_networks/Wirelesss_internet/Laboratories/office_capture/office_capture.pcapng')

# Declaring used dictionary -> MAC: [downlinlk bytes, uplink bytes]
mac = {} 

# Count the bytes of data packets:
nData_rx = 0
nData_tx = 0
nData = 0
print("\nScanning the capture...\n")

for packet in cap:
    
    # Handles malformed packets:
    try: 

        # Only if the it's a (QoS: 0x0028 -> 40) DATA (0x0020 -> 32) packet:
        if(packet.wlan.fc_type_subtype == '40' or packet.wlan.fc_type_subtype == '32'):

            # Finding destination address MAC addess:
            rx = packet.wlan.ra

            if rx in mac:
                mac[rx][0] = mac[rx][0] + int(packet.data.len)
            else:
                mac.setdefault(rx, [int(packet.data.len), 0])
            
            # Incrementing received data:
            nBytes_rx = int(packet.data.len)
            nData_rx = nData_rx + nBytes_rx

            # Attempt to take the source address:
            try:
                tx = packet.wlan.sa

                if tx in mac:
                    mac[tx][1] = mac[tx][1] + int(packet.data.len)
                else:
                    mac.setdefault(tx, [0, int(packet.data.len)])
                
                # Incrementing transmitted data:
                nBytes_tx = float(packet.data.len)
                nData_tx = nData_tx + nBytes_tx
                
            except:
                pass

            # Total data:
            nData = nData_tx + nData_rx

    # If problems, just skip:
    except:
        pass

print("Revealed " + str(nData) + " bytes of data!\n")

# Printing out the dictionary in the form MAC: [downlink bytes, uplink bytes]:
print("MACs revealed and correspondent transmitted and received bytes:\n")
for key, value in mac.items():
    print(key, ":", value)

# List of all the MAC addresses revealed:
mac_keys = mac.keys()
mac_list = []
for key in mac_keys:
    mac_list.append(key)


# Bytes in downlink and uplink of each revealed MAC:
downlink = []
uplink = []

for m in mac:
    downlink.append(mac[m][0])
    uplink.append(mac[m][1])


# Label locations:
x = np.arange(len(mac_list)) 

# Bar width:
width = 0.35

# Preparing figure:
fig, ax = plt.subplots()
rects1 = ax.bar(x - width/2, downlink, width, label='Downlink')
rects2 = ax.bar(x + width/2, uplink, width, label='Uplink')

# Add some text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('Bytes')
ax.set_title('Bytes transmitted and received by each captured MAC address')
ax.set_xticks(x)
plt.xticks(rotation=90)
ax.set_xticklabels(mac_list)
ax.legend()

# Place the value of a bar directly above it:
autolabel(rects1)
autolabel(rects2)

# Adapts the layout to the window:
fig.tight_layout()

# Shows the graph:
plt.show()