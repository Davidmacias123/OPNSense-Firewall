
# OPNsense Firewall & IDS – Purple Team Lab

## Project Overview
This repository documents the full deployment and configuration of a Purple Team security lab using **OPNsense**. The environment is designed to simulate real-world enterprise network security operations, including firewall enforcement, network segmentation, intrusion detection, attack simulation, and forensic traffic analysis.

The lab focuses on understanding how traffic flows through a firewall, how security rules affect that traffic, how intrusion detection systems identify malicious behavior, and how packet-level evidence validates security events. Each configuration step is visually documented to clearly show what is occurring within the environment.

---

## Lab Goals and Scope
The purpose of this lab is to demonstrate:

- Deployment of an OPNsense firewall from installation to production-ready configuration  
- Segmentation of internal networks to enforce traffic inspection  
- Static routing between isolated subnets  
- Creation and validation of firewall access control rules  
- Deployment and tuning of the Suricata Intrusion Detection System  
- Detection of reconnaissance activity using both default and custom IDS rules  
- Forensic packet capture and analysis to confirm attack behavior  

This lab mirrors workflows commonly used by SOC analysts, security engineers, and blue team operators.

---

## Environment Architecture

**Firewall Platform:** OPNsense (FreeBSD-based)  
**Attacker System:** Ubuntu Linux  
**Target System:** Windows Server  
**Virtualization Platform:** VirtualBox  

### Network Design
The network is intentionally segmented to ensure all traffic between systems passes through the firewall:

- **WAN:** Bridged adapter providing upstream connectivity  
- **LAN:** Host-only network (192.168.30.0/24)  
- **OPT1:** Host-only network (192.168.40.0/24)  

This design prevents direct host-to-host communication and forces all traffic to be inspected and logged by OPNsense.

---

## OPNsense Installation

The OPNsense ISO is downloaded from the official OPNsense website and used to create a new virtual machine.

During virtual machine creation:
- The operating system type is set to **BSD**
- The distribution is set to **FreeBSD**

The screenshot below shows the VirtualBox configuration screen where the OPNsense ISO is attached to the virtual machine. This step prepares the firewall for installation.

<img width="1918" height="1078" alt="creating virtual machine" src="https://github.com/user-attachments/assets/fc25432e-8fd2-45d7-8258-5a65ccd26e58" />

---

## Firewall Network Adapter Configuration

After creating the virtual machine, the network settings are configured. Three adapters are required to properly segment traffic:

- **Adapter 1 (WAN):** Bridged Adapter  
- **Adapter 2 (LAN):** Host-Only Adapter  
- **Adapter 3 (OPT1):** Host-Only Adapter  

Promiscuous Mode is set to **Allow All** on all adapters. This is required so that the Intrusion Detection System can observe and analyze all packets passing through the firewall interfaces.

Two separate host-only networks are created, each using a different subnet. This separation is critical because it allows routing rules, firewall rules, and IDS rules to be properly tested and validated.

The screenshot below shows the two host-only adapters configured with different network ranges.

<img width="1918" height="1075" alt="The two adapters i created for this firewall" src="https://github.com/user-attachments/assets/146c89ed-bbf1-4133-a4ab-80f29f166a88" />

---

## Installation Using Default Settings

The installer is accessed using the default **installer** account with the default password. All installation steps use default settings to establish a clean and predictable baseline.

Each screenshot below represents a stage of the installation process, including disk selection, filesystem configuration, and confirmation steps.

<img width="757" height="417" alt="defaults part 1" src="https://github.com/user-attachments/assets/e490d909-542b-4fc5-a9ee-ad09bde4fdac" />
<img width="717" height="532" alt="defaults part 2" src="https://github.com/user-attachments/assets/cd925306-bc46-42bf-ad8f-0ab745a5bd1c" />
<img width="736" height="402" alt="defaults part 3" src="https://github.com/user-attachments/assets/d53af99c-5e82-4f88-98f9-b7cce8c5ac16" />
<img width="747" height="417" alt="defaults part 4" src="https://github.com/user-attachments/assets/8603cf23-7e7a-414e-bd3d-2887bc5b18da" />
<img width="767" height="422" alt="defaults part 5" src="https://github.com/user-attachments/assets/27e1f32e-a28f-4017-a2a5-3fa537396997" />
<img width="751" height="423" alt="defaults part 6" src="https://github.com/user-attachments/assets/8d2c3d34-6cef-4523-aaea-60969c17dc1f" />
<img width="782" height="427" alt="defaults part 7" src="https://github.com/user-attachments/assets/3241b78d-eb8b-4c9a-a77a-a16d4ab182ab" />

---

## Post-Installation Disk Removal

After the first reboot, the virtual machine is powered off and the installation disk is removed. This step ensures that the firewall boots from the installed system rather than restarting the installer.

The screenshot below shows the removal of the installation disk from the VM storage settings.

<img width="970" height="637" alt="after rebooting it fastly turn it off and remove this disk so it starts saving the configurations" src="https://github.com/user-attachments/assets/145a2611-1984-4a67-809c-607b72f24015" />

---

## Interface Assignment

From the OPNsense console menu, interfaces are manually assigned:

- **WAN:** em0  
- **LAN:** em1  
- **OPT1:** em2  

This mapping ensures that each network adapter corresponds to the correct firewall interface.

<img width="745" height="418" alt="you will need to set the interfaces all over again but is okay part 2" src="https://github.com/user-attachments/assets/54604a70-f96b-4bbb-8f1f-586a22fb1a05" />

---

## Static IP Configuration

Static IP addresses are assigned to internal interfaces to prevent DHCP conflicts and ensure consistent routing behavior.

- **LAN:** 192.168.30.9/24  
- **OPT1:** 192.168.40.9/24  
- **WAN:** DHCP  

DHCP is disabled on LAN and OPT1 because DHCP is already handled at the VirtualBox network layer. HTTP management access is disabled to enforce encrypted HTTPS access only.

<img width="782" height="472" alt="configuring em1 explain every step david on what is going on part 2" src="https://github.com/user-attachments/assets/545adaee-34e5-4fa7-a7f4-b0488eeee190" />
<img width="872" height="452" alt="new OPNSENSE LAN WAN OPT" src="https://github.com/user-attachments/assets/74477b2a-555f-4d07-8f83-5e318ac5ccc4" />

---

## Firewall Rule Validation

Firewall rules are created to demonstrate how traffic is permitted or denied. ICMP traffic is initially blocked between the Ubuntu and Windows systems to confirm that firewall enforcement is working correctly.

The screenshots below show:
- The firewall rule configuration  
- The failed ping attempt  
- The firewall log entries confirming the block  

<img width="1908" height="913" alt="image" src="https://github.com/user-attachments/assets/49e7c659-3145-49c9-85cc-eda7a4b3add9" />
<img width="1185" height="773" alt="command is working i cant ping windows" src="https://github.com/user-attachments/assets/09f9da66-6cf9-4c56-a534-be2fae21229c" />
<img width="1907" height="917" alt="how to see all the block stuff on the firewall and you know the firewall rule is working" src="https://github.com/user-attachments/assets/395607da-e624-47f3-ad39-d54b4dba0c4c" />

---

## Intrusion Detection System Deployment

The Suricata IDS is enabled in promiscuous mode on both LAN and OPT1 interfaces. Emerging Threats Open rules are downloaded and enabled to provide baseline detection for common attack patterns.

The screenshots below show the IDS configuration interface and rule download process.

<img width="1905" height="913" alt="settings of the ids enabling promicious mode " src="https://github.com/user-attachments/assets/13411d63-f6a5-4f55-917e-a83465fdd7ba" />
<img width="1595" height="842" alt="enabling all the et rules " src="https://github.com/user-attachments/assets/c003f216-d7a6-4c82-95bf-4c36ba98468d" />

---

## Custom IDS Rule – Nmap Stealth Scan Detection

Default Suricata rules do not aggressively alert on stealth scans to reduce false positives. To address this limitation, a custom rule is created to detect abnormal SYN-only traffic patterns associated with Nmap stealth scanning.

The screenshots below show:
- The custom rule creation process  
- The rule appearing in the IDS rule list  
- The alert generated when the stealth scan is detected  

<img width="762" height="428" alt="add these command sin order for your ids to work" src="https://github.com/user-attachments/assets/cecdc7dd-ec47-4212-9eff-0e2a89c0899a" />
<img width="1905" height="911" alt="the rule we created is here" src="https://github.com/user-attachments/assets/ad607dfd-ad26-489c-9d80-1cc6909e8c89" />
<img width="1912" height="916" alt="ours ids is working with stealth command of nmap" src="https://github.com/user-attachments/assets/534aad5e-f6e1-46fe-b2f9-fb665a9304d2" />

---

## Forensic Packet Capture and Analysis

Packet capture is used to validate IDS alerts and analyze traffic behavior. The capture confirms a high volume of SYN packets generated by the Nmap stealth scan.

The screenshots below show:
- Packet capture configuration  
- Wireshark analysis  
- Evidence of SYN packet flooding  

<img width="1912" height="921" alt="we packet capture" src="https://github.com/user-attachments/assets/555a6a85-9e51-440b-bf73-8afab45ba147" />
<img width="1918" height="1018" alt="our wireshark packet of the packet capture" src="https://github.com/user-attachments/assets/844a0758-042f-4094-ad3c-02f80fc32325" />
<img width="1918" height="1078" alt="tcp floods" src="https://github.com/user-attachments/assets/a255c9d4-b8be-4489-bf41-b58d779b2c64" />
