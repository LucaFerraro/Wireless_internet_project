#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Attempt to detect the MAC addresses revealerd after sniffing in monitor mode. 
# MACs are added in a dictionary that has MACs themselves as key and many 
# statistics for each MAC

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
cap = pyshark.FileCapture('/Users/lucaferraro/Desktop/PoliMi/First_year/Wireless_networks/Wirelesss_internet/Wireless_internet_project/MAC_count2.pcapng')

# Declaring used dictionary -> MAC: [downlinlk B, uplink B, downlink Pkt, uplink pkt]
mac = {} 

# Count the bytes of data packets:
nData_rx = 0
nData_tx = 0
nData = 0

# Number of packet transmitted and received by each mac:
nPacket_tx = 0
nPacket_rx = 0
nPacket = 0

print("\nScanning the capture...\n")

for packet in cap:
    
    # Handles malformed packets:
    try: 

        # Only if the it's a (QoS: 0x0028 -> 40) DATA (0x0020 -> 32) packet:
        if(packet.wlan.fc_type_subtype == '40' or packet.wlan.fc_type_subtype == '32'):

            # Finding destination address MAC addess:
            rx = packet.wlan.ra

            if rx in mac:
                mac[rx][0] = mac[rx][0] + int(packet.data.len) # Number of downlink bytes 
                mac[rx][2] = mac[rx][2] + 1                    # Number of downlink packets
            else:
                mac.setdefault(rx, [int(packet.data.len), 0, 1, 0])
            
            # Incrementing received data:
            nBytes_rx = int(packet.data.len)
            nData_rx = nData_rx + nBytes_rx
            
            nPacket_rx = nPacket_rx + 1

            # Attempt to take the source address:
            try:
                tx = packet.wlan.sa

                if tx in mac:
                    mac[tx][1] = mac[tx][1] + int(packet.data.len) # Number of uplink bytes
                    mac[tx][3] = mac[tx][3] + 1                    # Number of uplink packets
                else:
                    mac.setdefault(tx, [0, int(packet.data.len), 0, 1])
                
                # Incrementing transmitted data:
                nBytes_tx = float(packet.data.len)
                nData_tx = nData_tx + nBytes_tx

                nPacket_tx = nPacket_tx + 1
                
            except:
                pass

            # Total data:
            nData = nData_tx + nData_rx
            nPacket = nPacket_tx + nPacket_rx

    # If problems, just skip:
    except:
        pass

print("Revealed " + str(nData) + " bytes of data!\n")
print("Total number of packet exchanged: " + str(nPacket))

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

# Number of downlink and uplink packets of each revealed MAC:
downlink_pkt = []
uplink_pkt = []

for m in mac:
    downlink.append(mac[m][0])
    uplink.append(mac[m][1])
    downlink_pkt.append(mac[m][2])
    uplink_pkt.append(mac[m][3])


# Label locations:
x = np.arange(len(mac_list)) 

# Bar width:
width = 0.35

""" Preparing figure for bytes """

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

"""
# Preparing figure for number of packets

rects3 = ax[1].bar(x - width/2, downlink_pkt, width, label='Downlink packets')
rects4 = ax[1].bar(x + width/2, uplink_pkt, width, label='Uplink packets')

ax[1].set_ylabel('Number of packets')
ax[1].set_title('Number of packets transmitted and received by each captured MAC address')
ax[1].set_xticks(x)
plt.xticks(rotation=90)

ax[1].set_xticklabels(mac_list)
ax[1].legend()

autolabel(rects3)
autolabel(rects4)

# Showing graphs:
fig[1].tight_layout()
plt.show()

"""