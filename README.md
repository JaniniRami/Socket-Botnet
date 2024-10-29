## T-409-TSAM: Assignment 5 - A5_56

### SECURITY REPORT FOR BONUS POINT IS AT THE END OF THE README FILE
### WIRETRACE IS IN A ```wiretrace.txt``` FILE.

The code consists of two main parts: the server and the client. The server acts as a peer-to-peer server in a botnet, providing commands for communication between peers on the network, while the client connects to one server and communicates with it using specific commands discussed below.

The program was successfully compiled and deployed on the TSAM server.

## Installation

### Server Installation
- You need to run the server before running the client.
- Note that port 4056 was used because our group number is A5_56.

```
bash
cd server
make
./tsamgroupA3_56 4056
```
### Client Installation
```
cd client
make
./client_tsamgroupA3_56 4056
```
## Documentation

### Server Implemented Commands
[1] HELO,<FROM_GROUP_ID>: When receiving a HELO command from a group, the server accepts it as an actual client (not a scam), as the client has identified itself. The server also sends HELO,A5_56 when connecting to other servers to identify itself as an actual peer.

[2] KEEPALIVE,<No. of Messages>: The server sends this message periodically (every one minute) to keep the connection between the server and client alive, while also informing other servers about how many messages are stored for them.

[3] GETMSGS,<GROUP ID>: Sent by a server to retrieve messages for a specific group. The server responds by sending SENDMSG commands containing stored messages for the requested group. Once the message is sent, it is deleted from the server storage and becomes the responsibility of the receiving server.

[4] SENDMSG,<TO GROUP ID>,<FROM GROUP ID>,<Message content>: This command sends a message from one group to another. If the destination is the server's group ID, it’s called a "0 hop" message and is received directly. If the destination is another server, the message is forwarded or stored until the recipient server is back online. Stored messages can be retrieved using GETMSGS commands.

[5] STATUSREQ: The server replies with STATUSRESP,<server, msgs held>,... listing servers for which it holds messages and the number of messages stored for each.


### Client Server Commands:
[1] LISTSERVERS: Requests the server to list all the other servers it is connected to.
[2] SENDMSG,GROUP ID,<message contents>: Sends a message to a specified server by passing it first to the local server, which then handles it according to its internal logic.
[3] GETMSG,GROUP ID: Retrieves the latest stored message for the specified group ID.




## Checklist
[1] Implement client and server as described above. All local commands to the server must be implemented by a separate client over the network

[2] Provide a wireshark trace of communication between your client and server for
all commands implemented in the client to server protocol

[3] Have been successfully connected to by an Instructor’s server. (Provide timestamped log)
 Timestamps:
 ```
[2024-10-23 00:21:41] Sent message to Group: Instr_1 IP: 130.208.246.249, Port: 5003 - HELO,A5_56
```
```
[2024-10-23 00:21:41] New message from Group:  IP: 130.208.246.249, Port: 5001 - SERVERS,Instr_1,130.208.246.249,5001;Instr_2,130.208.246.249,5002;A5_3,130.208.246.249,4003;NUMBER,130.208.246.249,5005;A5_56,130.208.246.249,-1;A5_99,89.160.215.77,-1;
```

[4] Successfully receive messages from at least 2 other groups (Provide timestamped
log)

Message 1: 
```
[2024-10-23 00:10:07] New message from Group: A5_3 IP: 130.208.246.249, Port: 51464 - SENDMSG,A5_56,ORACLE, “The greatest enemy of knowledge is not ignorance, it is the illusion of knowledge.”
— Stephen Hawking 
```

Message 2:
```
[2024-10-23 13:38:13] New message from Group:  IP: 130.208.246.249, Port: 4020 - SENDMSG,A5_56,A5_20,Hello from A5_20
```

[5]  Code is submitted as a single zip file, with README and Makefile. (Do not
include hg/git/etc. repositories or other hidden files!) The README describes how to
compile and run the code, lists the commands that are implemented in the client and server
and describes the behaviour of the server in response to these commands and potentially
other external events.

[6]  Code is well structured and documented. The server produces a readable log file
showing all received and sent commands and other useful information about the internal
state and behaviour of the server.

```
[7] BONUS: : Write a brief - no more than 1 page - description listing the several security issues of the botnet.


### Security Issues in the Botnet

1. **Trust in Peers (SERVERS and STATUSRESP Commands)**
   The server relies heavily on commands like `SERVERS` and `STATUSRESP` to exchange information with other peers. However, accepting these commands without proper validation introduces a risk of malicious peers misreporting or manipulating network information. A malicious peer could:
   - **Misreport the SERVERS list**: By providing fake or compromised server addresses, an attacker could reroute messages to malicious nodes, enabling eavesdropping, message interception, or message loss.
   - **Alter STATUSRESP responses**: A peer could falsely report that it holds messages for specific groups or provide incorrect hop counts to affect routing. This could lead to unnecessary delays or even permanent message loss.
   
   **Risk**: If these commands are trusted without verification, the server might inadvertently forward sensitive messages to untrusted peers, resulting in data breaches or disruption of communication.

2. **Hop Count Manipulation**
   The botnet relies on hop counts to manage message routing between servers. Malicious entities could manipulate hop counts to disrupt communication. For example:
   - A malicious peer could artificially lower the hop count, causing messages to be sent in loops or back to the sender without ever reaching the intended destination.
   - Alternatively, increasing the hop count could make the network think a message has been successfully routed when in fact, it hasn't, leading to message loss or undelivered communications.

   **Risk**: Manipulating hop counts can severely disrupt routing efficiency and reliability, increasing message delivery times or causing critical communications to be lost.

3. **Message Loss Due to Peer Crashes (GETMSGS Command)**
   The `GETMSGS` command is crucial for retrieving undelivered messages from other servers. However, if a peer collects messages from other servers but subsequently crashes or goes offline, all those messages could be lost. This scenario poses two major risks:
   - **Unintentional Message Loss**: A well-intentioned peer might request messages with the aim of delivering them but could experience a crash or network issue, causing those messages to be lost. This could effectively block communication between groups, especially if such crashes happen frequently.
   - **Malicious Interference**: A malicious actor could deliberately request messages and then go offline, hoarding and withholding them to disrupt the network. This could prevent critical messages from ever reaching their intended recipients.

   **Risk**: Frequent message loss due to peer instability or deliberate interference compromises the reliability of communication within the botnet, hindering group coordination.

4. **Denial of Service (DoS) Attacks**
   A malicious peer could exploit the server's reliance on periodic `KEEPALIVE` and message-exchange protocols by flooding the network with fake `KEEPALIVE` or `SENDMSG` commands. This could overwhelm legitimate servers, leading to:
   - **Resource Exhaustion**: Servers could become bogged down with processing fake requests, consuming CPU and memory resources, eventually leading to service disruptions or crashes.
   - **Message Flooding**: Attackers could also send an excessive number of fake messages, filling up server storage and bandwidth, thus preventing legitimate messages from being sent or received.

   **Risk**: A botnet is highly susceptible to DoS attacks if no protections are in place to limit or authenticate message and command requests.

### Recommendations for Mitigation

1. **Authentication of Peers**: To prevent malicious peers from manipulating network information, authentication mechanisms (such as digital certificates or cryptographic signatures) should be implemented to ensure that only trusted servers can participate in the botnet.

2. **Message Integrity and Validation**: Implement checks to verify the integrity of hop counts and ensure that peers cannot manipulate routing information. Additionally, servers should periodically validate the messages they hold, ensuring that a peer’s reported status (e.g., via `STATUSRESP`) matches its actual storage.

3. **Redundant Message Delivery**: Introduce mechanisms for message redundancy, such as storing copies of messages across multiple peers. If one peer goes offline or crashes, another peer can take over message delivery, reducing the risk of message loss.

4. **Rate Limiting and Resource Monitoring**: Implement rate limits on `KEEPALIVE` and message exchanges to prevent DoS attacks. Servers should monitor resource usage and deny or limit connections that exhibit suspicious or overwhelming activity patterns.
```