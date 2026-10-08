# Autonomous AI Cyber Commander

An autonomous AI-driven cybersecurity framework that detects network attacks, classifies malicious activity, dynamically deploys firewall rules, and remembers previous attacks for immediate response to recurring threats.

---

## Overview

**Autonomous AI Cyber Commander** is a real-time network defense system designed to combine:

- Network attack detection
- Event-driven security architecture
- AI-assisted security decision making
- Dynamic firewall enforcement
- eBPF/XDP packet filtering
- Attack correlation
- Attack history and memory
- Automated response to recurring attacks

The primary objective is to move from a traditional **detect-and-alert** security system toward an autonomous **detect-decide-respond** architecture.

Instead of only reporting an attack, the Cyber Commander analyzes the detected event, determines an appropriate response using an AI agent, dynamically deploys a firewall rule, and stores the response in attack memory.

When the same attack is detected again, the system can bypass the AI decision process and immediately enforce the previously learned blocking policy.

---

## Project Objective

The system is designed around the following security workflow:

```text
Incoming Network Traffic
          |
          v
    Attack Detection
          |
          v
      SecurityEvent
          |
          v
       EventBus
          |
          v
   Attack Correlation
          |
          v
     Decision Engine
          |
          v
       AI Agent
          |
          v
   Firewall Decision
          |
          v
    Firewall Manager
          |
          v
       eBPF / XDP
          |
          v
     XDP_DROP
```

For recurring attacks:

```text
Repeated Attack
      |
      v
Attack Memory Lookup
      |
      +---- Known Attack ----> Immediate Block
      |
      +---- New Attack ------> AI Analysis
                                  |
                                  v
                             Firewall Action
                                  |
                                  v
                            Store in Memory
```

---

## Key Features

### 1. Real-Time Attack Detection

The system monitors network traffic and identifies multiple attack patterns.

Currently supported detection modules include:

- SYN Flood
- HTTP Flood
- ICMP Flood
- Brute Force
- Port Scan
- ARP Spoofing

Additional attack simulations are maintained separately in the `attacks/` directory for testing and evaluation.

---

### 2. AI-Assisted Security Decisions

The Cyber Commander integrates an AI security agent to analyze detected events.

The AI agent receives structured security information such as:

- Attack type
- Source IP
- Target IP
- Confidence
- Connection count
- Failed attempts
- Unique ports
- Correlation information

The AI agent determines whether the event should be:

- Blocked
- Logged
- Monitored

The AI agent does not directly execute shell commands or modify the firewall.

Instead, it uses controlled firewall tools exposed by the Cyber Commander.

---

### 3. Dynamic Firewall Enforcement

Once a malicious event is approved for blocking, the system dynamically adds the attacker's IP address to the eBPF firewall blocklist.

Example:

```text
Attack Detected
      |
      v
AI Decision: BLOCK
      |
      v
FirewallTools
      |
      v
FirewallManager
      |
      v
eBPF blocklist map
      |
      v
XDP_DROP
```

This allows malicious packets to be dropped at the kernel/network-driver level before they reach normal user-space processing.

---

### 4. eBPF/XDP Firewall

The project uses **eBPF/XDP** for high-performance packet filtering.

The current firewall:

- Runs at the Linux kernel networking layer
- Maintains an eBPF blocklist map
- Checks incoming IPv4 source addresses
- Drops packets from blocked addresses
- Maintains packet statistics
- Supports temporary blocking policies

The core packet-processing decision is:

```text
Packet
  |
  v
Is IPv4?
  |
  +-- No --> XDP_PASS
  |
  +-- Yes
        |
        v
Is source IP in blocklist?
        |
        +-- No --> XDP_PASS
        |
        +-- Yes --> XDP_DROP
```

---

## Attack Memory

One of the major goals of the project is to avoid repeatedly performing expensive AI analysis for attacks that have already been identified.

The system maintains attack history containing information such as:

- Source IP
- Attack type
- Action taken
- Blocking duration
- Reason
- Enforcement policy
- Timestamp

For example:

```text
First SYN Flood
       |
       v
AI Analysis
       |
       v
BLOCK
       |
       v
Store Policy
```

If the same source performs the same attack again:

```text
Repeated SYN Flood
       |
       v
Attack Memory
       |
       v
Known Attack
       |
       v
Immediate BLOCK
```

This provides a faster response path for recurring threats.

---

## Attack Correlation

The Cyber Commander does not treat every security event completely independently.

The `AttackCorrelator` maintains recent events within a correlation window.

For example:

```text
Port Scan
    +
Brute Force
    +
HTTP Flood
    |
    v
Same Source IP
    |
    v
Correlated Attack Activity
```

Multiple attack types originating from the same source can increase the confidence that the source is malicious.

The correlation engine considers factors such as:

- Source IP
- Number of events
- Different attack types
- Average confidence
- Time window

This information is provided to the Decision Engine and AI agent.

---

## Project Architecture

```text
                       +----------------------+
                       |   Network Traffic    |
                       +----------+-----------+
                                  |
                                  v
                       +----------------------+
                       |   Attack Detectors   |
                       |                      |
                       | SYN Flood            |
                       | HTTP Flood           |
                       | ICMP Flood           |
                       | Brute Force          |
                       | Port Scan            |
                       | ARP Spoofing         |
                       +----------+-----------+
                                  |
                                  v
                       +----------------------+
                       |    SecurityEvent     |
                       +----------+-----------+
                                  |
                                  v
                       +----------------------+
                       |      EventBus        |
                       +----------+-----------+
                                  |
                                  v
                       +----------------------+
                       |  Attack Correlator   |
                       +----------+-----------+
                                  |
                                  v
                       +----------------------+
                       |   Decision Engine    |
                       +----------+-----------+
                                  |
                     +------------+------------+
                     |                         |
                     v                         v
             +---------------+         +---------------+
             | Attack Memory |         |   AI Agent    |
             +-------+-------+         +-------+-------+
                     |                         |
                     |                         v
                     |                +----------------+
                     |                | Firewall Tools |
                     |                +-------+--------+
                     |                        |
                     +------------------------+
                                              |
                                              v
                                  +----------------------+
                                  |  Firewall Manager    |
                                  +----------+-----------+
                                             |
                                             v
                                  +----------------------+
                                  |      eBPF / XDP      |
                                  +----------+-----------+
                                             |
                                             v
                                      XDP_DROP / PASS
```

---

## Repository Structure

```text
Autonomous-AI-Cyber-Commander/
│
├── attacks/
│   ├── syn_flood/
│   ├── http_flood/
│   ├── icmp_flood/
│   ├── brute_force/
│   ├── port_scan/
│   ├── arp_spoof/
│   ├── dns_tunneling/
│   ├── tcp_fin_scan/
│   ├── slow_http/
│   ├── dns_rebinding/
│   └── http_request_smuggling/
│
├── detectors/
│   ├── syn_flood_detector.py
│   ├── http_detector.py
│   ├── icmp_flood_detector.py
│   ├── brute_force_detector.py
│   ├── port_scan_detector.py
│   ├── arp_spoof_detector.py
│   └── __init__.py
│
├── cyber_commander/
│   ├── cyber_commander.py
│   ├── decision_engine.py
│   ├── attack_correlator.py
│   ├── attack_memory.py
│   ├── event_bus.py
│   ├── security_event.py
│   ├── ai_agent.py
│   ├── firewall_tools.py
│   ├── firewall_manager.py
│   ├── firewall_controller.py
│   ├── eBPF.c
│   └── __init__.py
│
├── README.md
└── .gitignore
```

---

## Attack Simulation Environment

The project is tested in an isolated virtualized laboratory environment.

A typical setup consists of:

```text
+-------------------+              +----------------------+
|    Kali Linux     |              |   Ubuntu Defender    |
|                   |              |                      |
| Attack Simulator  | ------------>| Cyber Commander      |
|                   |   Network    | Attack Detectors     |
| 192.168.56.103    |              | eBPF/XDP Firewall    |
+-------------------+              | 192.168.56.105       |
                                   +----------------------+
```

### Kali Linux

Used for controlled attack simulation and traffic generation.

### Ubuntu

Used as the protected system running:

- Attack detectors
- Cyber Commander
- AI decision engine
- Firewall manager
- eBPF/XDP firewall

---

## Tested Attack Simulations

The repository contains controlled attack simulations for evaluating the detection and response pipeline.

### SYN Flood

Generates repeated TCP SYN packets to evaluate SYN flood detection and dynamic blocking.

### HTTP Flood

Generates repeated HTTP requests to evaluate application-layer flooding detection.

### ICMP Flood

Generates high-volume ICMP echo requests to evaluate ICMP flood detection.

### Brute Force

Simulates repeated authentication attempts against a controlled laboratory service.

### Port Scan

Generates connection attempts across multiple ports to evaluate reconnaissance detection.

### ARP Spoofing

Simulates ARP-based network manipulation in an isolated laboratory environment.

### TCP FIN Scan

Tests whether stealth-oriented TCP scanning traffic can be classified as port scanning.

### DNS Tunneling

Generates unusual DNS query patterns to evaluate whether DNS-based covert traffic can be detected.

### Slow HTTP

Maintains incomplete or slowly progressing HTTP connections to test low-and-slow traffic patterns.

### DNS Rebinding

Simulates changing DNS resolution behavior in a controlled laboratory network.

### HTTP Request Smuggling

Tests suspicious HTTP request framing and conflicting request-header behavior.

---

## Technologies Used

### Programming

- Python
- C
- Bash

### Cybersecurity

- eBPF
- XDP
- BCC
- Scapy
- Linux networking
- Network traffic analysis

### Artificial Intelligence

- Google Gemini API
- AI-assisted security decision making
- Function calling
- Event-based reasoning

### Detection

- Rule-based network detection
- Statistical traffic analysis
- Attack correlation
- Security event generation

### Development Tools

- Git
- GitHub
- Linux
- Kali Linux
- Ubuntu
- VS Code

---

## Core Components

### Cyber Commander

The main orchestration layer responsible for starting detectors, receiving security events, and coordinating the response pipeline.

### SecurityEvent

A structured representation of a detected security event.

Example fields include:

```text
event_type
source_ip
target_ip
unique_ports
connection_count
service_port
failed_attempts
window_seconds
confidence
timestamp
```

### EventBus

Provides asynchronous communication between attack detectors and the main Cyber Commander.

### AttackCorrelator

Correlates multiple events from the same source within a defined time window.

### DecisionEngine

Coordinates the final response decision.

It:

1. Checks attack memory.
2. Immediately blocks known attacks when appropriate.
3. Sends new attacks to the AI agent.
4. Validates the AI response.
5. Executes approved firewall actions.
6. Stores successful blocking decisions.

### CyberDefenseAgent

The AI component responsible for analyzing security events and selecting an appropriate response.

### FirewallTools

Provides controlled firewall operations to the AI agent.

### FirewallManager

Manages the eBPF/XDP firewall and blocklist.

### eBPF Firewall

Performs packet-level source IP filtering using an eBPF map and XDP.

---

## Installation

Clone the repository:

```bash
git clone git@github.com:JP-05-CB/Autonomous-AI-cyber-commander-.git
cd Autonomous-AI-Cyber-Commander
```

Create a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

For systems where BCC/eBPF dependencies are provided through the OS package manager, install the required Linux packages separately.

---

## Configuration

Before running the Cyber Commander, configure:

### Network Interface

Set the protected network interface in the Cyber Commander configuration.

Example:

```python
INTERFACE = "enp0s8"
```

Replace the interface name with the interface used by the protected Ubuntu machine.

Find available interfaces with:

```bash
ip -br addr
```

### AI API Key

Configure the Gemini API key through an environment variable.

Example:

```bash
export GEMINI_API_KEY="YOUR_API_KEY"
```

Do not commit API keys or other secrets to GitHub.

---

## Running the Cyber Commander

From the project root:

```bash
cd cyber_commander
sudo python3 cyber_commander.py
```

The application starts:

1. eBPF/XDP firewall
2. Event processing
3. Attack detectors
4. Attack correlation
5. AI decision processing
6. Dynamic firewall enforcement

---

## Example Detection Flow

A new attack is detected:

```text
[DETECTOR]
SYN flood detected

        ↓

[SECURITY EVENT]
Event type: SYN_FLOOD
Source: 192.168.56.103
Confidence: HIGH

        ↓

[DECISION ENGINE]
New attack detected

        ↓

[AI AGENT]
Action: BLOCK

        ↓

[FIREWALL]
192.168.56.103 added to blocklist

        ↓

[eBPF/XDP]
Malicious packets → XDP_DROP
```

---

## Recurring Attack Flow

If the same source performs the same attack again:

```text
Attack Detected
      |
      v
Attack Memory Lookup
      |
      v
Known Attack
      |
      v
Skip AI Analysis
      |
      v
Use Stored Policy
      |
      v
Immediate Firewall Block
```

This reduces response latency for known threats.

---

## Security Design Principles

The AI agent is intentionally restricted from directly executing arbitrary system commands.

The security architecture follows these principles:

- Never trust an IP address generated by the AI.
- The AI can only operate on the event source IP.
- The target IP cannot be selected for blocking.
- Firewall actions are performed through controlled tools.
- Blocking duration is validated and limited.
- AI responses are validated before execution.
- Attack history is stored for future decisions.
- Network enforcement is handled by eBPF/XDP rather than arbitrary shell commands.

---

## Current Limitations

The current implementation has several limitations.

### IPv4 Focus

The current eBPF firewall primarily handles IPv4 traffic.

### ARP Enforcement

ARP spoofing detection is implemented separately, but the current IPv4 eBPF blocklist does not directly drop ARP packets.

### DNS Tunneling

DNS tunneling simulation is available for testing, but dedicated DNS tunneling detection is still a future enhancement.

### Application-Layer Attacks

Some attacks require application-layer visibility that cannot be reliably identified from packet headers alone.

### AI Dependency

New attack decisions may depend on the availability and response of the configured AI model.

---

## Future Enhancements

Planned improvements include:

- ML-based traffic classification
- CICIDS2017-based training and evaluation
- XGBoost/Random Forest integration
- DNS tunneling detection
- Advanced HTTP anomaly detection
- TCP fragmentation/evasion detection
- Improved ARP packet filtering
- IPv6 support
- More advanced attack correlation
- Adaptive firewall policies
- Automated eBPF rule generation
- Improved attack-memory persistence
- Security dashboard and visualization
- Detection and response latency measurement
- False-positive and false-negative evaluation
- Automated security report generation

---

## Project Goals

The long-term goal is to create a cybersecurity system capable of:

```text
DETECT
  ↓
CLASSIFY
  ↓
CORRELATE
  ↓
REASON
  ↓
DECIDE
  ↓
RESPOND
  ↓
REMEMBER
  ↓
RESPOND FASTER NEXT TIME
```

The project therefore combines **AI, network security, eBPF/XDP, automated response, and attack memory** into a unified autonomous cybersecurity architecture.

---

## Ethical Use

This project is intended for:

- Cybersecurity research
- Academic projects
- Controlled laboratory environments
- Defensive security experimentation
- Network security education
- Authorized penetration testing

Attack simulations must only be performed against systems and networks that you own or have explicit authorization to test.

Do not use the attack simulation components against public, third-party, or unauthorized systems.

---

## Authors

**Jaya Prasath**

B.E. Electronics and Communication Engineering  
College of Engineering Guindy (CEG), Anna University

Cybersecurity Minor  
Department of Computer Science and Engineering

---

## Project

**Autonomous AI Cyber Commander**

An autonomous cybersecurity framework for real-time attack detection, AI-assisted decision making, dynamic eBPF/XDP firewall enforcement, and attack-memory-based automated response.

---

## License

This project is developed for academic and cybersecurity research purposes.
```
