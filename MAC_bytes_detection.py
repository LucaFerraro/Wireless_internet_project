#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Attempt to detect the MAC addresses revealerd after sniffing in monitor mode. 
# MACs are added in a dictionary that has MACs themselves as key and many 
# statistics for each MAC

import pyshark
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
import sys
import time,os


""" This function attach a text label above each bar in *rects*, displaying its height. """
def autolabel(rects, ax):
    for rect in rects:
        height = rect.get_height()
        ax.annotate('{}'.format(height),
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')

""" This function activates a wireshark capture and uses it to run the program. """
def capturePackets(duration):
    seconds = int(duration)
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script")
    plt.ion()
    plt.show()

    while 1:
        #TODO: Sistemare il comando
        os.system('(sudo tshark -Ini wlp3s0 -s 256 -f "type mgt subtype beacon" -w beacon.pcap)&')
        time.sleep(seconds)
        os.system('killall tshark')


""" Checking command line parameters: if no special parameters are given, the program will run with out test capture, if the -file "PATH_TO_FILE"
    arguments are given, the program will run on the given capture file, if the -live CAPTURE_DURATION_IN_SECONDS arguments are given the program 
    will start capturing packets for the specified duration and then will execute the program on the captured packets. 
    Otherwise the program will stop running """

if (len(sys.argv) == 1):
    #cap = pyshark.FileCapture('Wireless_internet_project/MAC_count2.pcapng')
    #cap = pyshark.FileCapture('Wireless_internet_project/Sunday_morning_capture_MILAN.pcapng')
    cap = pyshark.FileCapture('Wireless_internet_project/Data_try.pcapng')
    #cap = pyshark.FileCapture('Wireless_internet_project/Monday_afternoon_capture_try_LIVORNO.pcapng')
    #cap = pyshark.FileCapture('Wireless_internet_project/Multimedia_internet_monday_first2min.pcapng')
    #cap = pyshark.FileCapture('Wireless_internet_project/Multimedia_internet_monday_middle.pcapng')
    #cap = pyshark.FileCapture("/home/fabio/Scrivania/Wireless Internet/Progetto/old/MAC_count2.pcapng")

elif (len(sys.argv) == 3):
    if sys.argv[1] == "-file":
        cap = pyshark.FileCapture(sys.argv[2])
    elif sys.argv[1] == "-live":
        capturePackets(sys.argv[2])

else:
    print("Invalid parameters: stopping execution...")
    sys.exit()

            

""" Starting the program """

# Declaring used dictionary -> MAC: [downlink B, uplink B, downlink Pkt, uplink pkt]
mac = {} 

# Count the bytes of data packets:
nData = 0

# Number of packet transmitted and received by each mac:
nPacket_tx = 0
nPacket_rx = 0
nPacket = 0

# Time the capture has last:
t_capture = 0

# For cumulative traffic: each emelent of a list contains the cumulative traffic measured with interval of T seconds
# meaning that the n-th element of the list contains the fraffic from time 0 to time n*T [s]:
cum_traffic_in = []
cum_traffic_out = []
n = 0
T = 30

# Threshold for MAC revealing (for data printing):
n_min_pkt = 20

print("\nScanning the capture...\n")

for packet in cap:

    # Time the packet has been sniffed fromt the beginning of the sniff:
    t_capture = packet.frame_info.time_relative
    
    # Handles malformed packets:
    try: 

        # Entering only if data (type = 2) but not no data:
        if((int(packet.wlan.fc_type) == 2) and 
            ((int(packet.wlan.fc_subtype) >= 0 and int(packet.wlan.fc_subtype) <= 3)) or
            (int(packet.wlan.fc_subtype) >= 8 and int(packet.wlan.fc_subtype) <= 11)):

            # Bytes of packet:
            nBytes_rx = 0
            nBytes_tx = 0

            # Finding destination address MAC addess:
            rx = packet.wlan.ra

            if rx in mac:
                mac[rx][0] = mac[rx][0] + int(packet.data.len) # Number of downlink bytes 
                mac[rx][2] = mac[rx][2] + 1                    # Number of downlink packets
            else:
                mac.setdefault(rx, [int(packet.data.len), 0, 1, 0, 0, 0])
            
            # Incrementing received data:
            nBytes_rx = int(packet.data.len)
            nData = nData + nBytes_rx
            nPacket_rx = nPacket_rx + 1

            # Updating cumulative downlink traffic:
            if n == 0: # If first packet:
                cum_traffic_in.append(nBytes_rx)
                n = n + 1
            
            elif t_capture <= n * T: # If packet in ((n-1)T, nT]:
                cum_traffic_out[-1] = cum_traffic_in[-1] + nBytes_rx

            else: # If packet in (nT, (n+1)T]:
                cum_traffic_in.append(cum_traffic_in[-1] + nBytes_rx)

            # Attempt to take the source address:
            try:
                tx = packet.wlan.sa

                if tx in mac:
                    mac[tx][1] = mac[tx][1] + int(packet.data.len) # Number of uplink bytes
                    mac[tx][3] = mac[tx][3] + 1                    # Number of uplink packets
                else:
                    mac.setdefault(tx, [0, int(packet.data.len), 0, 1, 0, 0])
                
                # Incrementing transmitted data:
                nBytes_tx = float(packet.data.len)
                nData = nData + nBytes_tx
                nPacket_tx = nPacket_tx + 1

                # Updating cumulative uplink traffic:
                if n == 0: # If first packet:
                    cum_traffic_in.append(nBytes_tx)
                    n = n + 1
            
                elif t_capture <= n * T: # If packet in ((n-1)T, nT]:
                    cum_traffic_out[-1] = cum_traffic_in[-1] + nBytes_tx

                else: # If packet in (nT, (n+1)T]:
                    cum_traffic_in.append(cum_traffic_in[-1] + nBytes_tx)
            
            # No source address in the packet, just skip:
            except:
                pass

            # If packet reception time in [nT, (n+1)T]:
            if t_capture > n*T:
                n = n + 1

    # Packet malformed, just skip:
    except:
        pass

# Tot number received packets:
nPacket = nPacket_tx + nPacket_rx

# Writing info on average downlink and uplink rate as Bytes/(elapsed_time):
for m in mac:
    
    # Avg downlink rate:
    mac[m][4] = mac[m][0] * 8 / float(t_capture)

    # Avg uplink rate:
    mac[m][5] = mac[m][2] * 8 / float(t_capture)


# Printing general info on the capture:
print("Capture time: " + str(t_capture))
print("Revealed " + str(nData) + " bytes of data.")
print("Total number of packet exchanged: " + str(nPacket) + ".")

# Printing out the dictionary:
print("\nMACs revealed and correspondent transmitted and received bytes:\n")
for key, value in mac.items():
    print(key, ":")
    print("\tUplink Bytes", value[0])
    print("\tUplink Packets", value[1])
    print("\tDownlink Bytes", value[2])
    print("\tDownlink Packets", value[3])
    print("\tUplink Rate", value[4])
    print("\tDownlink Rate", value[5])
    print("\n")

# List of all the MAC addresses revealed; considers only MACss with a min number of tx and rx packets:
mac_keys = mac.keys()
mac_list = []
for key in mac_keys:
    if (mac[key][2] >= n_min_pkt) or (mac[key][3] >= n_min_pkt):
        mac_list.append(key)

# Bytes in downlink and uplink of each revealed MAC:
downlink = []
uplink = []

# Number of downlink and uplink packets of each revealed MAC:
downlink_pkt = []
uplink_pkt = []

# Preparing lists for later plotting:
for m in mac_list:
    downlink.append(mac[m][0])
    uplink.append(mac[m][1])
    downlink_pkt.append(mac[m][2])
    uplink_pkt.append(mac[m][3])

# Lists for traffic exchanged every T seconds:
traffic_out = []
traffic_in = []

# Preparing traffic lists:
traffic_in.append(cum_traffic_in[0])
for index in cum_traffic_in[1:]:
    traffic_in.append(cum_traffic_in[index] - cum_traffic_in[index - 1])

traffic_out.append(cum_traffic_out[0])
for index in cum_traffic_out[1:]:
    traffic_out.append(cum_traffic_out[index] - cum_traffic_out[index - 1])


""" PREPARING FIGURES """

# Label locations:
x = np.arange(len(mac_list)) 

# Bar width:
width = 0.35

### Preparing figure for bytes ###

fig, (ax1, ax2) = plt.subplots(1, 2)
rects1 = ax1.bar(x - width/2, downlink, width, label='Downlink')
rects2 = ax1.bar(x + width/2, uplink, width, label='Uplink')

# Add some text for labels, title and custom x-axis tick labels, etc.
ax1.set_ylabel('Bytes')
ax1.set_title('Bytes transmitted and received by each captured MAC address')
ax1.set_xticks(x)
ax1.set_xticklabels(mac_list)
ax1.legend()
plt.setp(ax1.xaxis.get_majorticklabels(), rotation=90)

# Place the value of a bar directly above it:
autolabel(rects1, ax1)
autolabel(rects2, ax1)

### Preparing figure for exchanged packets ###

rects3 = ax2.bar(x - width/2, downlink_pkt, width, label='Downlink packets')
rects4 = ax2.bar(x + width/2, uplink_pkt, width, label='Uplink packets')

ax2.set_ylabel('Number of packets')
ax2.set_title('Number of packet transmitted and received by each captured MAC address')
ax2.set_xticks(x)
ax2.set_xticklabels(mac_list)
ax2.legend()
plt.setp(ax2.xaxis.get_majorticklabels(), rotation=90)

autolabel(rects3, ax2)
autolabel(rects4, ax2)

# Adapts the layout to the window and resize window:
plt.subplots_adjust(bottom=0.20)
F = plt.gcf()
F.set_size_inches(18.5, 10.5, forward=True)

### Showing the graphs ###
plt.show()