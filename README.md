# SOC in a Box - Virtual Security Operations Center

This project is a self-contained virtual Security Operations Center (SOC) built in collaboration with **Securado**. It simulates a real-world enterprise environment using Virtual Machines (VMs), security tools, and attack-defense scenarios. The purpose is to understand and demonstrate how Security Information and Event Management (SIEM) systems work in detecting, analyzing, and responding to threats.

## 🔧 Tools & Technologies

- **Kali Linux**: Used for penetration testing and generating attacks (e.g., Hydra).
- **Windows Server 2022**: Configured with **Active Directory** and **Event Logging**.
- **pfSense**: Used as the firewall for network segmentation and monitoring.
- **SIEM System**: For centralized log collection, correlation, and alerting.
- **rsyslog** (Linux) and **nxlog** (Windows): Log forwarding to SIEM.
- **VirtualBox**: All components run as VMs.
- **MySQL / Elasticsearch**: Backend database for SIEM data.


## 🧪 Key Features

- Simulated attacks using **SQLmap**.
- Detection and blocking using **Firewall rules**.
- Log collection from Windows and Linux using **rsyslog/nxlog**.
- Active Directory setup to mirror a real company structure with departments and users.
- Visual monitoring using dashboards and log correlation.

## 🚀 How to Run

1. Import all VMs into VirtualBox.
2. Configure network interfaces for each machine:
   - One NAT
   - One NAT Network for segmentation.
3. Configure network interfaces for pfsense:
   - One NAT
   - One NAT Network of kali.
   - One NAT Network of Win.
3. Boot the following in order:
   1. pfSense
   2. Windows Server (enable AD, logging, nxlog)
   3. Kali Linux (use attack scripts)
   4. SIEM Server (run Flask or backend services)
4. Launch the SIEM frontend at `http://<SIEM-IP>:5000`

## 📊 Logs & Alerting

The SIEM system parses logs using regex patterns and flags:
- Failed logins (Event ID 4625)
- Successful logins (Event ID 4624)
- Suspicious activity (Hydra attack, brute-force, port scan, SQLmap)

## ✅ Lessons Learned

- Deep understanding of firewall rules, NAT, and IDS/IPS.
- Building and tuning a custom SIEM pipeline.
- Correlating logs from multiple sources.
- Real-world experience in detection engineering.

## 🏢 Developed With

This project was developed during a security training with **Securado**.

## 📜 License

This project is for educational and demonstration purposes.

