Network Security Tasks - How to Run
1. Install Dependencies
python3 setup.py
2. Task 1 - Telnet (Plain Text)

Open 3 terminals:

Terminal 1 - Capture Packets
cd task1_telnet
python3 capture_and_analyze.py capture 2323 telnet.pcap lo
Terminal 2 - Start Server
python3 telnet_server.py
Terminal 3 - Run Client
python3 telnet_client.py

Login:

username: student
password: password123

Example commands:

whoami
secret
exit
Stop Capture & Analyze

Press Ctrl+C in Terminal 1, then:

python3 capture_and_analyze.py analyze telnet.pcap 2323
3. Task 2 - SSH (Encrypted)

Open 3 terminals:

Terminal 1 - Capture Packets
cd task2_ssh
python3 capture_and_analyze.py capture 2222 ssh.pcap lo
Terminal 2 - Start Server
python3 ssh_server.py
Terminal 3 - Run Client
python3 ssh_client.py
Stop Capture & Analyze

Press Ctrl+C in Terminal 1, then:

python3 capture_and_analyze.py analyze ssh.pcap 2222
4. Compare Telnet vs SSH
python3 capture_and_analyze.py compare telnet.pcap ../task2_ssh/ssh.pcap
5. Task 3 - JWT Web Application
cd task3_jwt
python3 app.py

Open in browser:

http://localhost:5000