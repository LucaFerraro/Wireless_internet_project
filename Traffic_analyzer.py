#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Attempt to detect the MAC addresses revealed after sniffing in monitor mode. 
# MACs are added in a dictionary that has MACs themselves as key and many 
# statistics for each MAC

import pyshark
import numpy as np
import matplotlib.pyplot as plt, itertools
import matplotlib
import sys
import time,os

''' PARAMETERS '''

# Used for counting the bytes tr/rx over time.
TIME_WINDOW_CUMULATIVE_TRAFFIC = 30 

# Used for plotting: considering only MACs that have rx or tx at least this percentage
# of the max number of packets tx/tx. 0 will plot all the registered MACs:
PLOT_RATIO = 1/100

""" Loading MAC Vendors list """
#load vendor list from file: the first 3 bytes of each MAC address are assigned to the manufacturer.
f = open(os.path.join(sys.path[0],'oui2.txt'),'r')
vendor_mac = []
vendor_name = []
for line in f:
    if "(base 16)" in line:
        fields = line.split("\t")
        vendor_mac.append(fields[0][0:6])
        vendor_name.append(fields[2])

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
def capturePackets(interface, duration):
    seconds = int(duration)
    capture_filter = "type data and (subtype data or subtype data-cf-poll or subtype data-cf-ack-poll or subtype qos-data or subtype qos-data-cf-ack or subtype qos-data-cf-poll or subtype qos-data-cf-ack-poll)"
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script")
    plt.ion()
    plt.show()
    command = 'sudo tshark -Ini ' + interface + ' -f ' + capture_filter + ' -w live_capture.pcap'
    print(command)

    while 1:
        #TODO: Sistemare il comando
        os.system(command)
        time.sleep(seconds)
        os.system('killall tshark')

""" This function allows to find out the vendor associated to the input MAC address """
def convertMACAddress(mac):
    #search first 3 bytes of mac in vendor_mac
    red_mac = mac[0:8].upper()
    red_mac = red_mac.replace(':','')
    #get the corresponding vendor or unkown
    try:
        index = vendor_mac.index(red_mac)
    except ValueError:
        index = -1
    #increment the corresponding bin
    if index!=-1:
        v_name = vendor_name[index]
    else:
        v_name = "unknown \n"

    return v_name


""" Checking command line parameters: if no special parameters are given, the program will run with out test capture, if the -file "PATH_TO_FILE"
    arguments are given, the program will run on the given capture file, if the -live CAPTURE_DURATION_IN_SECONDS arguments are given the program 
    will start capturing packets for the specified duration and then will execute the program on the captured packets. 
    Otherwise the program will stop running """

# if no additional arguments are provided it will run a default capture (testing purposes)
if (len(sys.argv) == 1):
    cap = pyshark.FileCapture(os.path.join(sys.path[0],"Filtered_capture_WEDNESDAY_MILAN.pcapng"))

# if -file "PATH TO FILE" is provided, the program will launch the program on the provided capture
elif (len(sys.argv) == 3):
    if sys.argv[1] == "-file":
        cap = pyshark.FileCapture(sys.argv[2])

# if -live "INTERFACE" "DURATION" is provided, the program will start a live capture with the given data and will analyze it
elif(len(sys.argv) == 4):
    if sys.argv[1] == "-live":
        cap = capturePackets(sys.argv[2], sys.argv[3])

else:
    print("Invalid parameters: stopping execution...")
    sys.exit()


""" Starting the program """

# Declaring used dictionary -> MAC: [downlink B, uplink B, downlink Pkt, uplink pkt]
mac = {} 

# Count the bytes of data packets:
nData = 0

# Number of packet transmitted and received by each mac:
nPacket = 0

# Time the capture has last:
t_capture = 0

# For cumulative traffic: each element of a list contains the cumulative traffic measured with interval of T seconds
# meaning that the n-th element of the list contains the traffic from time 0 to time n*T [s]:
# Lists for traffic exchanged every T seconds:
traffic_out = []
traffic_in = []
cum_traffic_in = []
cum_traffic_out = []
n = 0
T = TIME_WINDOW_CUMULATIVE_TRAFFIC

# Threshold for MAC revealing (for data printing):
plot_ratio = PLOT_RATIO

print("\nScanning the capture...\n")

for packet in cap:

    # Time the packet has been sniffed from the beginning of the sniff:
    t_capture = float(packet.frame_info.time_relative)
    
    # Handles malformed packets:
    try: 

        # Entering only if type is Data or QoS Data but not no data:
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

            # Attempt to take the source address:
            try:
                tx = packet.wlan.sa

                if tx in mac:
                    mac[tx][1] = mac[tx][1] + int(packet.data.len) # Number of uplink bytes
                    mac[tx][3] = mac[tx][3] + 1                    # Number of uplink packets
                else:
                    mac.setdefault(tx, [0, int(packet.data.len), 0, 1, 0, 0])
                
                # Incrementing transmitted data:
                nBytes_tx = int(packet.data.len)
            
            # No source address in the packet, just skip:
            except:
                pass
            
            # Updating traffic curve:
            if (t_capture >= n*T): # if t_capture in [(n+1)T, (n+2)T]
                traffic_in.append(nBytes_rx)
                traffic_out.append(nBytes_tx)
                n = n + 1

            else: # if t_capture in [nT, (n+1)T]
                traffic_in[n-1] = traffic_in[n-1] + nBytes_rx
                traffic_out[n-1] = traffic_out[n-1] + nBytes_tx

            nData = nData + nBytes_rx
            nPacket = nPacket + 1


    # Packet malformed, just skip:
    except:
        pass

# Tot number received packets:


# Writing info on average downlink and uplink rate as Bytes/(elapsed_time):
for m in mac:
    
    # Avg downlink rate:
    mac[m][4] = mac[m][0] * 8 / float(t_capture)

    # Avg uplink rate:
    mac[m][5] = mac[m][2] * 8 / float(t_capture)


# Printing general info on the capture:
print("Capture time: " + str(t_capture) + ".")
print("Revealed " + str(nData) + " bytes of data.")
print("Total number of packet exchanged: " + str(nPacket) + ".")

# Printing out the dictionary:
print("\nMACs revealed and correspondent transmitted and received bytes:\n")
unknown_vendors = []
for key, value in mac.items():
    vendor = convertMACAddress(key)
    if vendor == "unknown \n":
        unknown_vendors.append(key)
    else:
        print("Vendor: " + vendor)
        print(key, ":")
        print("\tUplink Bytes", value[1])
        print("\tUplink Packets", value[3])
        print("\tDownlink Bytes", value[0])
        print("\tDownlink Packets", value[2])
        print("\tUplink Rate", value[5])
        print("\tDownlink Rate", value[4])
        print("\n")

print("MAC addresses with unknown vendor: ")
print(unknown_vendors)

# Finding max number of packets tx/rx (for plotting data):
down_pkts = [] # List of rx packets from all the revealed MACs.
up_pkts = []   # List of tx packets from all the revealed MACs.
for i in mac.values():
    down_pkts.append(i[2])
    up_pkts.append(i[3])

# Joining the two lists and finding the max value:
pkts = up_pkts + down_pkts
max_pkts = max(pkts)

# List of all the MAC addresses revealed. c
# Considers only MACs with a number of tx or rx packets >= of a percentage of the max tx/rx packets:
mac_keys = mac.keys()
mac_list = []

for key in mac_keys:
    if (mac[key][2] >= max_pkts*plot_ratio) or (mac[key][3] >= max_pkts*plot_ratio):
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


# Preparing cumulative traffic lists:
cum_traffic_in.append(traffic_in[0])
for index in range(1,len(traffic_in)):
    cum_traffic_in.append(traffic_in[index] + cum_traffic_in[index - 1])

cum_traffic_out.append(traffic_out[0])
for index in range(1,len(traffic_out)):
    cum_traffic_out.append(traffic_out[index] + cum_traffic_out[index - 1])


""" BYTES AND PACKETS GRAPHS """

# Label locations:
x = np.arange(len(mac_list)) 

# Bar width:
width = 0.35

### Preparing figure for bytes ###

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15,8))
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

""" TRAFFIC GRAPHS """

# Horizontal axis:
time_axis = []
for i in range(0, len(cum_traffic_in)):
    time_axis.append(TIME_WINDOW_CUMULATIVE_TRAFFIC*i)

### Received traffic ###
fig_in, (plt_cum_in, plt_in) = plt.subplots(1, 2, figsize=(15,8))

plt_cum_in.plot(time_axis, cum_traffic_in)
plt_cum_in.set_xlabel('Time [s]')
plt_cum_in.set_ylabel('Bytes')
plt_cum_in.set_title('Cumulative traffic received')

plt_in.plot(time_axis, traffic_in)
plt_in.set_xlabel('Time [s]')
plt_in.set_ylabel('Bytes')
plt_in.set_title('Received traffic trend')

### Transmitted traffic ###
fig_out, (plt_cum_out, plt_out) = plt.subplots(1, 2, figsize=(15,8))

plt_cum_out.plot(time_axis, cum_traffic_out)
plt_cum_out.set_xlabel('Time [s]')
plt_cum_out.set_ylabel('Bytes')
plt_cum_out.set_title('Cumulative traffic transmitted')

plt_out.plot(time_axis, traffic_out)
plt_out.set_xlabel('Time [s]')
plt_out.set_ylabel('Bytes')
plt_out.set_title('Transmitted traffic trend')

""" SHOWING ALL GRAPHS """
plt.show()