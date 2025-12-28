# OPNSense-Firewall
Architected a Purple Team lab using OPNsense, creating custom firewall and IDS rules with Suricata. Simulated Nmap attacks and validated detections through live logs and packet capture analysis.


I added my diagram of this project of what is exactly that is going on with this project so you have an idea how everything is working. I also created a packet tracer as well as a simulation or an idea what is going on so you are able to visualize and have an idea what this project is about.
We will be creating our own using opnsense. you will need to download OPNSENSE ISO on this link https://opnsense.org/download/. once you successfully dowloaded you will need to create  a virtual machine. on the part where it says ISO Image you will need to put the ISO of the firewall. For operating system is BSD and OS Distribution is FreeBSD.

<img width="1918" height="1078" alt="creating virtual machine" src="https://github.com/user-attachments/assets/fc25432e-8fd2-45d7-8258-5a65ccd26e58" />

---


After that you will create the virtual machine and then go to settings and go to network part of your configurations and create three adapters. Your first adapter will be bridge adapter, that will be your WAN, the second adapter will be host only, that will be your LAN, and lastly your third adpater will be also host only that will be your optional 1, and for all three adapters for Promiscuous Mode it should all be "Allow All". After that you will create two adapters. On the adapter portion i chose 192.168.30.1, that will be your network address, for the subnet mask keep it as 255.255.255.0. For the DHCP Server portion for server address for my example it would be 192.168.30.2 so it can follow the same subnet as your ipv4address. and for your lower address bound for dhcp it should be 192.168.30.13 and the upper address bound it would be 192.168.30.254 and server mask 255.255.255.0. And on my second adapter i chose 192.168.40.1 as the adapter and for the server address 192.168.40.2 lower address bound 192.168.40.11 upper address bound 192.168.40.254 with a subnet mask 255.255.255.0. The reason why these adapters we are making them on different subnet is in order for this project to work.

<img width="1918" height="1075" alt="The two adapters i created for this firewall" src="https://github.com/user-attachments/assets/146c89ed-bbf1-4133-a4ab-80f29f166a88" />

---



In order for this firewall is able to work and you are able to use all the settings that OPNsense has. Once you complete that you will login as installer, and the password would be opnsense, and you will use all the defaults settings options that opnsense has
<img 
  width="757" height="417" alt="defaults part 1" src="https://github.com/user-attachments/assets/e490d909-542b-4fc5-a9ee-ad09bde4fdac" />

  ---

<img width="717" height="532" alt="defaults part 2" src="https://github.com/user-attachments/assets/cd925306-bc46-42bf-ad8f-0ab745a5bd1c" />



---

<img width="736" height="402" alt="defaults part 3" src="https://github.com/user-attachments/assets/d53af99c-5e82-4f88-98f9-b7cce8c5ac16" />

---

<img width="747" height="417" alt="defaults part 4" src="https://github.com/user-attachments/assets/8603cf23-7e7a-414e-bd3d-2887bc5b18da" />


---


<img width="767" height="422" alt="defaults part 5" src="https://github.com/user-attachments/assets/27e1f32e-a28f-4017-a2a5-3fa537396997" />


---


<img width="751" height="423" alt="defaults part 6" src="https://github.com/user-attachments/assets/8d2c3d34-6cef-4523-aaea-60969c17dc1f" />


---


<img width="782" height="427" alt="defaults part 7" src="https://github.com/user-attachments/assets/3241b78d-eb8b-4c9a-a77a-a16d4ab182ab" />

---

ONce the Virtual machines satrt rebooting, and is activating to the main screen you saw when you turned it on you will immediately turn it off and go to your opnsense settings go to storage, and then delete the disc. the reason why is because so your configurations save, if you dont do that they wont save.

<img width="970" height="637" alt="after rebooting it fastly turn it off and remove this disk so it starts saving the configurations" src="https://github.com/user-attachments/assets/145a2611-1984-4a67-809c-607b72f24015" />


---

after that you will turn on the machine again and at the end you will log in as root, and the password should be opnsense. you will press1 to assign interfaces. WAN should be em0, LAN em1, and OPT1 em2.

<img width="745" height="418" alt="you will need to set the interfaces all over again but is okay part 2" src="https://github.com/user-attachments/assets/54604a70-f96b-4bbb-8f1f-586a22fb1a05" />


---
Then you will click 2 to set interface ip address and for this project i made it static because is better is more convenient. And for my lan i chose 192.168.30.9, 24for bit counts subnets and no for the ipv6 portion and for the enable dhcp portion server on our LAN that should also be a no, the reason why we already did it when we created our adapters, and turning dhcp on, and having dhcp on the adapters, it will overlap, and there will be networking issues, and a lot of misconfigurations. And you will also put no on HTTP becasue that is port 80 and is not as secured as port 443 which is HTTPS.



<img width="782" height="472" alt="configuring em1 explain every step david on what is going on part 2" src="https://github.com/user-attachments/assets/545adaee-34e5-4fa7-a7f4-b0488eeee190" />

---
Then you will do the exact same thing for OPT, and you will go base on your second network adapter that you created. For WAN, that will be DHCP. The end of your results should be looking something like this.

<img width="872" height="452" alt="new OPNSENSE LAN WAN OPT" src="https://github.com/user-attachments/assets/74477b2a-555f-4d07-8f83-5e318ac5ccc4" />

---

If all you rconfigurations are correct you will be able to log in to the GUI. The way how you access it you will type your LAN ip address and inputted on your google search.

<img width="1918" height="1078" alt="type the LAN ip and that should take you here and then you will login as root and pass opnsense" src="https://github.com/user-attachments/assets/af4ca3bb-3c68-40c1-b543-4a57852d3686" />


---

Then you will go to System- configurations -  Wizard and complete the configurations and you are able to change your opnsense name and add a different password. Once you complete that you apply the changes.

<img width="937" height="537" alt="image" src="https://github.com/user-attachments/assets/dc55c3b7-b121-4096-98a5-31793e3a77c1" />


---

Then for this part you should have two other virtual machines, you can use any, but the ones that i chose is an ubuntu and windows server. for ubuntu make sure that you change the network portion to host only adapter and choose adapter threee on the name portion and for promiscuous mode do ALLOW VMS.


<img width="1647" height="318" alt="we will configure ubuntu and it should have these and then we will turn it on, the same for windows machine but with adapter 4" src="https://github.com/user-attachments/assets/db72bec2-83b5-4c42-a7ff-562b8ce63f21" />


----


And do the exact same thing for your second virtual machine as well



<img width="1642" height="303" alt="configuring windows and turning it on" src="https://github.com/user-attachments/assets/ab5f8285-7603-4908-af94-8a50a6d088d7" />




---
## Creating default gateways for both virtual machines

After this you will turn on both machines and go to the command prompt.

For ubuntu
you will type ip route to see if it already has a default gateway, if not we will crete one. In order for both machines to talk to each other you need to have a default gateway on both machines. Then you will type ip route get 192.168.40.11 and it will tell you the network is unreachable. Now you will type sudo ip route add default via 192.168.30.9 dev enp0s3. The reason why because that is the ip of your lan and this virtual machine will connect to em1. then you will type ip route to make sure a default gateway is creted, and thenip route get 192.168.30.9, it should look something like my screen. the 192.168.40.11 is the IP of my windows virtual machine.


<img width="1258" height="792" alt="ubuntu commands for pinging windows official correct one" src="https://github.com/user-attachments/assets/224e540f-71d0-4097-a72a-4285a80d56d1" />


---
Now you will do the exact same thing on your windows machine.

The first command would be route -p add 0.0.0.0 mask 0.0.0.0 192.168.40.12

Then the second command should be route add 192.168.30.0 mask 255.255.255.0 192.168.40.12 The route print and then you will put ipconfig and you will see that you have a gateway now

<img width="1046" height="798" alt="commands for windows to ping ubuntu part 1" src="https://github.com/user-attachments/assets/c658297c-301a-458a-a0bd-1c9f2aa6ff89" />



----

<img width="1131" height="807" alt="commands for windows to ping ubuntu part 2" src="https://github.com/user-attachments/assets/02bde43e-e194-4872-8a3f-7b481ab9c8ce" />



----
## Creating a separate rule for your OPT1 To work
Then you will need to create a rule for the OPT1 in order for it to have access, no rule, meaining everything will deny. The only thing you will have to change is the source make sure you put OPT1 net.


<img width="1580" height="827" alt="only editing this on the firewall to give opt access" src="https://github.com/user-attachments/assets/00f3d55f-a3a8-4013-aae9-2c67b8f041fa" />


----

## Creating Firewall Rules:

Now you will have to create two rules on your LAN. The first rule would be to block ICMP from your source to your destination, for this case that will be my ubuntu to my windows server. Make sure you follow these steps that are highlighted.


<img width="1908" height="913" alt="image" src="https://github.com/user-attachments/assets/49e7c659-3145-49c9-85cc-eda7a4b3add9" />

----


After that i will go to your ubuntu and try to ping your windows and you will see that is not working.


<img width="1185" height="773" alt="command is working i cant ping windows" src="https://github.com/user-attachments/assets/09f9da66-6cf9-4c56-a534-be2fae21229c" />


----
Then i will go to my firewall log files live view and you will see that that my configurations on my opnsense are working is blocking the ICMP from ubuntu to windows server machine. 

<img width="1907" height="917" alt="how to see all the block stuff on the firewall and you know the firewall rule is working" src="https://github.com/user-attachments/assets/395607da-e624-47f3-ad39-d54b4dba0c4c" />



---


After that i will create a second rule to allow icmp from ubuntu to windows and now i will be able to ping my windows again on my ubuntu and you will also see on your live view that the traffic for icmp is now allowed so thast how you know the configurations of the firewall is working.


<img width="1908" height="911" alt="image" src="https://github.com/user-attachments/assets/2cc5dc34-8f45-40f7-90db-82506c5024d5" />


---


<img width="1195" height="797" alt="created the other rule now i i can" src="https://github.com/user-attachments/assets/bf2c1db0-6b23-4254-b44a-0497b6aae787" />


----
<img width="1905" height="905" alt="lan working dont need to post this " src="https://github.com/user-attachments/assets/05d07db4-d17a-4b44-97cd-88ed1b3a01e5" />


---

## Creating INTRUSION DETECTION SYSTEM

NOw we will create an IDS on our firewall. You will go to services - intrusion detection system - Administration.
We will configure the settings of the IDS. enable and prmiscious mode, and for the interfaces make sure is both of your host only adapters, and make sure you also put their host networks you should find them on the firewall virtual machine it should be your em1 and em2 your lan and opt 1.




<img width="1905" height="913" alt="settings of the ids enabling promicious mode " src="https://github.com/user-attachments/assets/13411d63-f6a5-4f55-917e-a83465fdd7ba" />


---

Go to download and you will download all the ET Open Rules, and after you are done make sure you click  enable selected and download and update rules.

<img width="1595" height="842" alt="enabling all the et rules " src="https://github.com/user-attachments/assets/c003f216-d7a6-4c82-95bf-4c36ba98468d" />


---


<img width="1897" height="915" alt="now we download them" src="https://github.com/user-attachments/assets/b87f6f9c-66e5-4e74-961a-5a9d500593cb" />



----

Then you will go to the rule tabs and you will need to download all the rules when you are searching for scan and Nmap, and then you will click enable and then apply. And you will see a green play button in the top right of your GUI that means your IDS is activated.


<img width="1902" height="860" alt="enable scan to all six pages" src="https://github.com/user-attachments/assets/7fea5217-3021-4a3e-b81b-5d19e330a59c" />


---

<img width="1895" height="923" alt="do the same for nmap" src="https://github.com/user-attachments/assets/2c914d39-2a48-4c0f-b762-b1f4aceef994" />


---

Just so you know these rules your firewall wont be able to detect  the command stealth of nmap and the reason why becasue Nmap stealth scans are designed to look normal. Suricata which is the IDS inside OPNsense) won’t alert unless traffic clearly matches a known attack pattern. Many stealth scans don’t cross that line, so no alert fires unless you teach Suricata exactly what to look for. When you run the command Nmap sends SYN packets only, no full TCP handshake, no payload, and often slow timing -t2, -t3 to avoid rate based detection. What all this does to the scan  pretty much makes normal connection attempts, legitimate user traffic, broken or dropped connections. From the IDS perspective this is ambigious not obviously malicious. 
suricata doesnt alert by default , suricata works on rules. default rules focus on exploits, malware, known attack siganatures, and high conifidence malicious behavior. Default suricata rules do not aggresively flag low rate SYN scans, half open TCP attempts and reconnaissance that looks polite for the reason is to avoid false positives, enterprises scan their own networks all the time, and flagging every SYN would break SOC workflows. commands that actually would work and detect are aggresive scans like "nmap -A 192.168.40.11.

## Before Creating our own rule for the stealth command to work



Now we will create our own rule so the stealth command works. but first we will go to OPNSense CLI and we will press 8 for the terminal and type "ifconfig |" more which will show us our interfaces more in-depth to confirm that the IDS is enabled on those interfaces. The | more lets us press Enter to scroll down since it doesn't support scrolling up. As we can see from my image, we're looking for SIMPLEX as apart of the flags of our em1 and em2 interfaces, which should be our LAN and OPT1 if you've followed my instructions. This confirms that our IDS is actively scanning both interfaces which is a good sign.


<img width="773" height="427" alt="showing our ids is working on both adapters" src="https://github.com/user-attachments/assets/5195600f-d0b3-4524-abd3-c025a24e7031" />



----

Next we want to head back to our Firewall GUI and go to Interfaces -> Settings to ensure that Hardware CRC, Hardware TSO, and Hardware LRO are all checked to disable checksum offload and segmentation offload.



<img width="935" height="810" alt="image" src="https://github.com/user-attachments/assets/454073e6-f067-4c91-9109-c1ea4a96029a" />


----


## Creating our own rule for the stealth command to work

Now in order for the stealth commadns to work  we will have to create a custom rule  but first we need to go to the command line interface of opnsense type 8 and enter and put this command on the CLI "sed -i '' 's/checksum-validation: yes/checksum-validation: no/g' /usr/local/etc/suricata/suricata.yaml &&configctl ids restart"

This command will disable checksum validation which basically means Suricata won't be checking is the packet is valid. This will prevent nmap from bypassing scans through sending intentionally malformed/incomplete packets which is critial. Now we will create the rule, the rule is "echo 'alert tcp any any -> any any (msg:"Smart NMAP Stealth Scan Detected"; flow:stateless; flags:S; threshold:type threshold, track by_src, count 20, seconds 5; sid:1000001; rev:1;)' > /usr/local/etc/suricata/rules/local.rules && configctl ids reload"




<img width="762" height="428" alt="add these command sin order for your ids to work" src="https://github.com/user-attachments/assets/cecdc7dd-ec47-4212-9eff-0e2a89c0899a" />

---

Now we will go to our rules and you will see that the rule was created.


<img width="1905" height="911" alt="the rule we created is here" src="https://github.com/user-attachments/assets/ad607dfd-ad26-489c-9d80-1cc6909e8c89" />




-----

The reason why this rule works because i pretty much said in my rule that in my environment this behavior is not normal, and i made it detect steal commands and made ambigious traffic into contextual malivious behavior and i will be able to detect anything whats going on in my firewall if there is any malivious behavior going on.


----


Now we will go to our ubuntu and type the command "sudo nmap -sS -Pn 192.168.40.11" and go to our firewall alerts and as you can see it detected the stealth command.


<img width="1912" height="916" alt="ours ids is working with stealth command of nmap" src="https://github.com/user-attachments/assets/534aad5e-f6e1-46fe-b2f9-fb665a9304d2" />




------

## Creating  forensic packet capture


Now we will go to interfaces --- diagnostics --- packet capture and we will capture everything that is going on in our environment, and we will input the same command again on our ubuntu the nmap command and then we will stop the capture and view the capture by downloading it and analyze it on wireshark and filter it, and as you can see the flood of SYN packets sent by Nmap.

<img width="1912" height="921" alt="we packet capture" src="https://github.com/user-attachments/assets/555a6a85-9e51-440b-bf73-8afab45ba147" />



----



<img width="1918" height="1018" alt="our wireshark packet of the packet capture" src="https://github.com/user-attachments/assets/844a0758-042f-4094-ad3c-02f80fc32325" />



-----

<img width="1918" height="1078" alt="tcp floods" src="https://github.com/user-attachments/assets/a255c9d4-b8be-4489-bf41-b58d779b2c64" />






