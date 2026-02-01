# NetDeflect v2.5 - PaintSecure Edition 🎨🛡️

**Modified by martin**

**NetDeflect PaintSecure Edition** is an advanced DDoS mitigation and detection tool for Linux-based systems with enhanced security features. It captures, analyzes, and classifies traffic in real-time, blocks malicious IPs using AI-powered detection, provides comprehensive behavioral analysis, and sends detailed alerts to keep you informed of any attacks.

## 🚀 **What's New in PaintSecure Edition**

### **Enhanced Security Features:**
- 🧠 **AI-Powered Threat Detection** - Advanced behavioral analysis and anomaly detection
- 🔍 **Multi-layer DDoS Protection** - Comprehensive attack pattern recognition
- 📊 **Behavioral Analysis Engine** - Real-time IP behavior monitoring and scoring
- 🌍 **Threat Intelligence Integration** - External threat feed updates and blacklisting
- ⚡ **Adaptive Rate Limiting** - Dynamic traffic control based on patterns
- 🎯 **Automated Pattern Learning** - Auto-detection and classification of new attack vectors
- 🔒 **Zero-day Protection** - Detection of unknown attack patterns
- 🌐 **GeoIP Blocking** - Geographic-based traffic filtering
- 📈 **IP Reputation System** - Dynamic scoring and tracking of suspicious IPs

### **Advanced Firewall Support:**
- **Multiple Firewall Systems**: iptables, ufw, ipset, blackhole routing, nftables
- **Multi-firewall Mode**: Primary + secondary firewall support
- **Challenge-Response System**: CAPTCHA-like verification for suspicious IPs
- **Temporary Blocking**: Time-based IP blocking with automatic cleanup

### **Enhanced Monitoring:**
- **Real-time Metrics**: CPU, memory, network statistics
- **Attack Severity Classification**: LOW, MEDIUM, HIGH, CRITICAL
- **Confidence Scoring**: AI-based attack confidence levels
- **Comprehensive Reporting**: Detailed attack analysis and mitigation reports

----

## 📋 **Requirements**

- **Operating System**: Linux (Ubuntu, Debian, CentOS, etc.)
- **Python**: 3.6 or higher
- **Network Tools**: tcpdump, tshark (Wireshark CLI)
- **Permissions**: Root/sudo access for network capture and firewall management
- **Memory**: Minimum 512MB RAM (1GB+ recommended for AI features)
- **Storage**: 1GB free space for logs and capture files

----

## 🛠️ **Installation**

### **Quick Install (Ubuntu/Debian)**
```bash
# Install system dependencies
sudo apt update
sudo apt install python3 python3-pip tcpdump tshark -y

# Clone the repository
git clone https://github.com/MartinSAMP/PaintSecure
cd PaintSecure

# Install Python dependencies
pip3 install psutil requests

# Run PaintSecure Edition
sudo python3 netdeflect.py
```

### **CentOS/RHEL Installation**
```bash
# Install system dependencies
sudo yum install python3 python3-pip tcpdump wireshark-cli -y

# Clone and setup
git clone https://github.com/MartinSAMP/PaintSecure
cd PaintSecure
pip3 install psutil requests

# Run with sudo
sudo python3 netdeflect.py
```

### **First Run Setup**
On first use, you will need to run `netdeflect.py` several times to complete the initial setup and configuration file generation.

----

## ⚙️ **Configuration**

The PaintSecure Edition uses an enhanced configuration system with advanced options:

### **Basic Configuration (settings.ini)**
```ini
[ip_detection]
ip_method = opendns
fallback_methods = google_dns,ipify,icanhazip

[capture]
network_interface = eth0
promiscuous_mode = true
buffer_size = 64

[triggers]
trigger_mode = MP
pps_threshold = 15000
mbps_threshold = 30
enable_adaptive_threshold = true
adaptive_sensitivity = 0.7

[firewall]
firewall_system = blackhole
enable_multi_firewall = false
secondary_firewall = iptables

[advanced_mitigation]
enable_ai_analysis = true
enable_behavioral_analysis = true
enable_pattern_detection = true
enable_geo_blocking = false
blocked_countries = CN,RU,KR,IR

[threat_intelligence]
enable_threat_feeds = true
enable_tor_blocking = true
update_frequency = 3600

[rate_limiting]
enable_rate_limiting = true
requests_per_second = 100
```

### **Advanced Features Configuration**
```ini
[ip_reputation]
enable_reputation_system = true
reputation_threshold = 50
decay_rate = 0.1

[security]
enable_encryption = true
enable_audit_log = true
audit_log_retention = 90

[advanced]
enable_zero_day_protection = true
enable_syn_flood_protection = true
enable_dns_amplification_protection = true
```

----

## 🎯 **Attack Detection Methodology**

PaintSecure Edition uses a sophisticated multi-layered approach:

### **1. Signature-based Detection**
- Matches traffic against 50+ known attack patterns
- Real-time pattern matching with configurable thresholds
- Support for TCP flags, protocol analysis, and payload inspection

### **2. AI-Powered Behavioral Analysis**
- **Packet Rate Analysis**: Detects unusual packet transmission patterns
- **Payload Size Variance**: Identifies suspicious payload size distributions
- **Timing Pattern Analysis**: Recognizes bot-like request timing
- **Anomaly Scoring**: 0-1 confidence scale for threat assessment

### **3. Threat Intelligence Integration**
- **External Feed Updates**: Automatic updates from threat databases
- **Malicious IP Blacklists**: Integration with Spamhaus, EmergingThreats
- **ASN-based Blocking**: Block entire network ranges
- **Tor/VPN Detection**: Optional blocking of anonymization services

### **4. Zero-day Protection**
- **Pattern Learning**: Automatically detects new attack patterns
- **Entropy Analysis**: Identifies encrypted/obfuscated payloads
- **Statistical Anomaly Detection**: Baseline traffic comparison
- **Auto-signature Generation**: Creates new detection rules

### **5. Geographic Analysis**
- **GeoIP Lookup**: Real-time country identification
- **Country-based Blocking**: Block traffic from specific regions
- **ASN Analysis**: Autonomous System Number filtering
- **VPN/Proxy Detection**: Identify traffic through anonymization services
----

## 📊 **File Structure**

```
NetDeflect-PaintSecure/
├── netdeflect.py                    # Main application (PaintSecure Edition)
├── settings.ini                     # Enhanced configuration file
├── notification_template.json       # Discord webhook template
├── methods.json                     # Attack signature database
├── README.md                        # This documentation
└── application_data/
    ├── captures/                    # Packet capture files (.pcap)
    ├── ips/                        # Detected malicious IP lists
    ├── attack_analysis/            # Detailed attack reports
    ├── logs/                       # System and attack logs
    ├── patterns/                   # Auto-detected attack patterns
    ├── reputation/                 # IP reputation database
    ├── blacklists/                 # Blocked IP history
    ├── whitelists/                 # Trusted IP lists
    └── new_detected_methods.json   # Auto-discovered attack signatures
```

----

## 🔗 **External API Integration**

PaintSecure Edition can integrate with external security services:

### **Supported Integration Methods**
- **Single IP Mode**: Send one IP per request
- **Batch Mode**: Send multiple IPs in groups
- **Bulk Mode**: Send all IPs in one request

### **Authentication Support**
- **Bearer Token**: OAuth2/API key authentication
- **Basic Auth**: Username/password authentication
- **Custom Headers**: Flexible header-based authentication

### **Configuration Example**
```ini
[external_firewall]
enable_api_integration = true
api_endpoint = https://api.example.com/firewall/block
auth_method = bearer
auth_token = your_api_token_here
sending_mode = batch
max_ips_per_batch = 100
request_body_template = {"source": "PaintSecure", "ips": {{IP_LIST}}}
```

----

## 🤖 **AI and Machine Learning Features**

### **Behavioral Analysis Engine**
- **Traffic Profiling**: Builds baseline profiles for normal traffic patterns
- **Anomaly Detection**: Identifies deviations from established baselines
- **Learning Algorithms**: Continuously improves detection accuracy
- **False Positive Reduction**: Smart filtering to reduce legitimate traffic blocking

### **Pattern Recognition System**
- **Automatic Signature Generation**: Creates new attack signatures from traffic analysis
- **Pattern Clustering**: Groups similar attack patterns for better classification
- **Confidence Scoring**: Assigns reliability scores to detected patterns
- **Adaptive Thresholds**: Automatically adjusts detection sensitivity

### **Zero-day Attack Detection**
- **Entropy Analysis**: Detects encrypted or obfuscated attack payloads
- **Statistical Analysis**: Identifies unusual traffic characteristics
- **Behavioral Fingerprinting**: Creates unique signatures for new attack types
- **Real-time Learning**: Updates detection models during operation
----

## 🛡️ **Supported Attack Types**

PaintSecure Edition can detect and mitigate various attack types:

### **Layer 3/4 Attacks**
- **SYN Flood**: TCP SYN packet flooding
- **UDP Flood**: UDP packet flooding
- **ICMP Flood**: ICMP ping flooding
- **TCP RST/FIN Flood**: TCP connection manipulation
- **Fragmented Packet Attacks**: IP fragmentation abuse

### **Application Layer Attacks**
- **HTTP/HTTPS Flood**: Web server overwhelming
- **Slowloris**: Slow HTTP connection attacks
- **DNS Amplification**: DNS reflection attacks
- **NTP Amplification**: Network Time Protocol abuse
- **SSDP Amplification**: Simple Service Discovery Protocol abuse

### **Advanced Attack Patterns**
- **Botnet Traffic**: Coordinated attack detection
- **Low-and-Slow Attacks**: Stealthy long-duration attacks
- **Mixed Protocol Attacks**: Multi-vector attack combinations
- **Encrypted Payload Attacks**: Obfuscated attack detection
- **Zero-day Exploits**: Unknown attack pattern recognition

----

## 📈 **Monitoring and Reporting**

### **Real-time Dashboard**
```
[NetDeflect v2.5 - PaintSecure Edition][14:30:25]
================================================================================
           IP Address: [192.168.1.100]
                  CPU: [15%]
                 MB/s: [5]
   Packets Per Second: [1,250]
        Blocked Count: [0]

Enabled Features:
  • AI Analysis | Behavioral Analysis | Pattern Detection
  • Threat Intelligence | Rate Limiting | Geo-Blocking
```

### **Attack Reports**
- **Pre/Post Mitigation Statistics**: Traffic comparison before and after blocking
- **Attack Classification**: Detailed attack type and severity analysis
- **IP Reputation Scoring**: Threat level assessment for detected IPs
- **Mitigation Effectiveness**: Success rate of blocking actions
- **Geographic Analysis**: Country and ASN information for attackers

### **Log Files**
- **Main Log**: `application_data/netdeflect-paintsecure.log`
- **Attack Analysis**: `application_data/attack_analysis/[timestamp].txt`
- **Blocked IPs**: `application_data/blacklists/blocked_ips.txt`
- **Auto-detected Patterns**: `application_data/new_detected_methods.json`

----

## 🔔 **Notification System**

### **Discord Webhook Integration**
PaintSecure Edition sends detailed attack notifications via Discord:

```json
{
  "title": "⚠️ DDoS Attack Mitigated: #123",
  "description": "PaintSecure detected and responded to a potential attack.",
  "fields": [
    {
      "name": "📊 Pre-Mitigation Stats",
      "value": "• Packets/s: 25,000\n• Mbps: 200\n• CPU: 85%"
    },
    {
      "name": "🛡️ Post-Mitigation Results", 
      "value": "• Status: Mitigated\n• IPs Blocked: 15\n• Attack Type: SYN Flood"
    }
  ],
  "author": {
    "name": "PaintSecure - mod by martin"
  }
}
```

### **Email and SMS Alerts** (Optional)
- **SMTP Integration**: Email notifications for critical attacks
- **SMS Gateway Support**: Text message alerts for high-severity incidents
- **Custom Webhooks**: Integration with third-party monitoring systems
----

## 🚨 **Usage Examples**

### **Basic Monitoring**
```bash
# Start PaintSecure with default settings
sudo python3 netdeflect.py

# Monitor specific interface
sudo python3 netdeflect.py --interface eth1

# Enable verbose logging
sudo python3 netdeflect.py --verbose
```

### **Advanced Configuration**
```bash
# Run with custom config file
sudo python3 netdeflect.py --config custom_settings.ini

# Enable all AI features
sudo python3 netdeflect.py --enable-ai --enable-behavioral --enable-geo

# Test mode (no actual blocking)
sudo python3 netdeflect.py --test-mode
```

### **Attack Simulation Testing**
```bash
# Test with hping3 (SYN flood simulation)
hping3 -S -p 80 --flood target_ip

# Test with UDP flood
hping3 -2 -p 53 --flood target_ip

# Monitor PaintSecure response in real-time
tail -f application_data/netdeflect-paintsecure.log
```

----

## 🔧 **Troubleshooting**

### **Common Issues**

#### **Permission Denied Errors**
```bash
# Ensure proper permissions
sudo chmod +x netdeflect.py
sudo chown root:root netdeflect.py

# Run with sudo
sudo python3 netdeflect.py
```

#### **Network Interface Not Found**
```bash
# List available interfaces
ip link show
# or
ifconfig -a

# Update settings.ini with correct interface name
network_interface = eth0  # Change to your interface
```

#### **Tshark/Tcpdump Not Found**
```bash
# Ubuntu/Debian
sudo apt install tcpdump tshark wireshark-common

# CentOS/RHEL
sudo yum install tcpdump wireshark-cli

# Arch Linux
sudo pacman -S tcpdump wireshark-cli
```

#### **High Memory Usage**
```ini
# Reduce packet capture size in settings.ini
[capture]
packet_count = 5000  # Reduce from default 10000
buffer_size = 32     # Reduce from default 64

[performance]
enable_packet_sampling = true
sampling_rate = 0.5  # Sample 50% of packets
```

### **Performance Optimization**

#### **For High-Traffic Servers**
```ini
[performance]
max_worker_threads = 20
enable_compression = true
enable_packet_sampling = true
sampling_rate = 0.1

[advanced_mitigation]
enable_ai_analysis = false  # Disable for better performance
contributor_threshold = 50  # Higher threshold
```

#### **For Low-Resource Systems**
```ini
[triggers]
packet_count = 2000
detection_threshold = 500

[advanced_mitigation]
enable_behavioral_analysis = false
max_pcap_files = 5
```

----

## 📚 **Advanced Features Guide**

### **Custom Attack Signatures**
Create custom attack detection patterns in `methods.json`:

```json
{
  "valid_ip_attacks": {
    "Custom_HTTP_Flood": "474554202f",
    "Custom_DNS_Query": "0001000100000000"
  },
  "spoofed_ip_attacks": {
    "Custom_SYN_Flood": "0x02"
  }
}
```

### **IP Reputation Management**
```bash
# View current IP reputation scores
cat application_data/reputation/ip_scores.json

# Manually whitelist an IP
echo "192.168.1.50" >> application_data/whitelists/trusted_ips.txt

# View blocked IP history
cat application_data/blacklists/blocked_ips.txt
```

### **Threat Intelligence Feeds**
Configure custom threat feeds in settings.ini:
```ini
[threat_intelligence]
enable_threat_feeds = true
custom_feeds = https://your-threat-feed.com/ips.txt,https://another-feed.com/malicious.txt
update_frequency = 1800  # 30 minutes
```

----

## 🤝 **Contributing**

We welcome contributions to the PaintSecure Edition! Here's how you can help:

### **Bug Reports**
- Use GitHub Issues to report bugs
- Include system information and log files
- Provide steps to reproduce the issue

### **Feature Requests**
- Suggest new detection algorithms
- Propose UI/UX improvements
- Request integration with new services

### **Code Contributions**
- Fork the repository
- Create feature branches
- Submit pull requests with detailed descriptions
- Follow Python PEP 8 coding standards

----

## 📄 **License**

This project is licensed under the MIT License - see the original NetDeflect repository for details.

**PaintSecure Edition Modifications** by martin are also released under the same MIT License.

----

## 🙏 **Acknowledgments**

- **Original NetDeflect**: Created by the NetDeflect team
- **PaintSecure Enhancements**: Modified by martin
- **Threat Intelligence**: Powered by Spamhaus, EmergingThreats, and other security feeds
- **Community**: Thanks to all contributors and users providing feedback

----


**NetDeflect v2.5 - PaintSecure Edition** - Advanced DDoS Protection with AI-Powered Security 🎨🛡️


*Modified by martin - Enhancing cybersecurity one packet at a time*
