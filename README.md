## introduction
Learn the basics of traffic analysis with Wireshark and how to find anomalies on your network!

Link: https://tryhackme.com/room/wiresharkpacketoperations

In this room, we will cover the techniques and key points of traffic analysis with Wireshark and detect suspicious activities.
# Task 2:Nmap Scans 
Use the “Desktop/exercise-pcaps/nmap/Exercise.pcapng” file.
What is the total number of the “TCP Connect” scans?
**Ans:100**

**the filter**: **tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size > 1024** 

<img width="700" height="500" alt="aa" src="https://github.com/user-attachments/assets/f5472c31-5b61-44de-97f6-d6d446fa091b" />
