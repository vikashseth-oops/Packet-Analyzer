# 🚀 DPI Engine & Packet Analyzer - Interview Guide & Deep Explainer

> **How to use this guide:** Read this before any technical interview! It covers everything from a 30-second elevator pitch to deep networking concepts, system architecture, concurrency design, and expected interview questions with model answers.

---

## 📌 1. The 30-Second Elevator Pitch

> *"I built a high-performance, multi-threaded **Deep Packet Inspection (DPI) Engine** in **C++17** coupled with a modern **Node.js Express & Vanilla JS Web Dashboard**. The engine reads raw network PCAP traffic, parses headers from Layer 2 to Layer 7, extracts Server Name Indication (SNI) from unencrypted TLS handshakes to classify encrypted HTTPS applications (like YouTube, TikTok, Facebook), and enforces multi-threaded firewall rules with 0% thread starvation. The web frontend provides real-time traffic visualization, 5-tuple flow inspection, one-click app blocking, and PCAP export capabilities."*

---

## 🧠 2. Core Problem & Real-World Context

### What is Deep Packet Inspection (DPI)?
Standard firewalls inspect only **Layer 3 (IP)** and **Layer 4 (Port)** headers. For example, blocking port `443` blocks *all* HTTPS traffic.

**DPI looks inside Layer 7 (Application Payload)**. It can distinguish whether port `443` traffic is going to **YouTube**, **Google**, or **TikTok**, allowing granular rules like *"Block YouTube, but allow Google Workspace"*.

### Real-World Applications:
- **Enterprise Security & Next-Gen Firewalls (NGFW)**: Blocking unauthorized applications (P2P torrents, social media).
- **ISPs & Telecom**: Traffic classification and bandwidth prioritization.
- **Parental Controls & Content Filtering**: Web filtering at gateway routers.

---

## 🌐 3. Networking Fundamentals (Must-Know for Interviewers)

### A. The Nesting Doll Structure of a Packet
Every packet captured in a `.pcap` file is wrapped in headers:
```
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 2: Ethernet Header (14 bytes) -> MAC addresses                   │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ Layer 3: IPv4 Header (20 bytes) -> Source IP, Destination IP       │ │
│ │ ┌────────────────────────────────────────────────────────────────┐ │ │
│ │ │ Layer 4: TCP/UDP Header (8-20 bytes) -> Source/Dest Ports      │ │ │
│ │ │ ┌────────────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Layer 7: Payload (TLS Client Hello with SNI Hostname)     │ │ │ │
│ │ │ └────────────────────────────────────────────────────────────┘ │ │ │
│ │ └────────────────────────────────────────────────────────────────┘ │ │
│ └────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

### B. What is the Five-Tuple?
A connection/flow is uniquely identified by **5 values**:
1. **Source IP** (e.g., `192.168.1.100`)
2. **Destination IP** (e.g., `142.250.185.206`)
3. **Source Port** (e.g., `54321`)
4. **Destination Port** (e.g., `443`)
5. **Protocol** (`TCP = 6`, `UDP = 17`)

*Interview Tip:* *"All packets sharing the exact same 5-tuple belong to the same TCP/UDP flow."*

### C. How Does SNI Extraction Work on Encrypted HTTPS Traffic?
Even though HTTPS encrypts web traffic, **the initial TLS handshake cannot be encrypted** because the server doesn't know which SSL certificate to serve yet!

1. Browser sends `TLS Client Hello` (record type `0x16`, handshake type `0x01`).
2. Inside extensions, extension `0x0000` is the **Server Name Indication (SNI)**.
3. The hostname (e.g., `www.youtube.com`) is present in **plaintext**.
4. Our `SNIExtractor` parses these exact binary byte offsets to extract the domain name before encryption starts!

---

## ⚙️ 4. System Architecture & Concurrency Design

### The Multi-Threaded Pipeline (Producer-Consumer)

```
┌─────────────────┐
│   PCAP Reader   │ (Reads raw packets from file)
└────────┬────────┘
         │  FiveTupleHash % num_lbs
         ▼
┌─────────────────┐
│ Load Balancers  │ (2 LB threads distribute packets)
└────────┬────────┘
         │  (FiveTupleHash >> 16) % fps_per_lb  <-- Decoupled Hashing Fix!
         ▼
┌─────────────────┐
│ FastPath Workers│ (4 FP threads: State Tracking, SNI Extract, Rule Check)
└────────┬────────┘
         │  Output Queue
         ▼
┌─────────────────┐
│ Output Writer   │ (Writes forwarded packets to output.pcap)
└─────────────────┘
```

### Why Flow Pinning to Worker Threads is Essential
If packets from the *same* connection were sent to random worker threads, threads would need to lock a shared global flow table, causing **severe lock contention**.

**Solution:** By hashing the 5-tuple, all packets for a specific connection are pinned to the **same FastPath worker thread**. This allows each FastPath worker to maintain its own `ConnectionTracker` flow map **without any mutex locking** during flow lookups!

---

## 🛠️ 5. Key Engineering Bugs Solved (Impression Boosters!)

If an interviewer asks: *"What challenging bugs did you face and fix?"*, share these:

### 1. Thread Starvation Fix (Modulo Hashing Collision)
- **Problem:** LB thread selected using `hash % 2`, and inner FP thread was selected using `hash % 2`. This caused math collision: LB0 sent 100% of packets to FP0 and 0% to FP1! FP1 and FP2 received 0 traffic (50% thread starvation).
- **Fix:** Decoupled hashing by shifting hash bits: `(hash >> 16) % num_fps_`. Now traffic is balanced across all 4 worker threads.

### 2. Memory Safety & Dangling Pointer Fix
- **Problem:** `PacketJob` struct held a raw pointer `const uint8_t* payload_data` pointing inside `std::vector<uint8_t> data`. When `PacketJob` was moved/copied across thread queues, `data` reallocated heap memory, leaving `payload_data` as a dangling pointer.
- **Fix:** Removed raw pointers and replaced with offset-based dynamic accessor `payloadData() { return data.data() + payload_offset; }`.

### 3. Pointer Underflow Prevention in QUIC SNI
- **Problem:** Outer loop evaluated `payload + i - 5` when `i < 5`, causing negative pointer offsets (out-of-bounds read).
- **Fix:** Guaranteed safe index bounds by enforcing `i >= 5`.

---

## 💻 6. Full-Stack Web Architecture

- **Backend (`web/server.js`)**: Express.js REST API serving as a bridge to `dpi_engine.exe` via C++ subprocesses. Handles multi-part file uploads (`multer`), rule persistence, and streaming log outputs.
- **Frontend Dashboard (`web/public/`)**: Handcrafted **Greenish Teal (`#0d9488`) & Lime ("Tello" `#84cc16`)** SPA with Chart.js charts for application distribution and 4-thread load balancing stats.

---

## 🎯 7. Top Technical Interview Q&A

### Q1: How do you handle high packet throughput without memory leaks?
> **Answer:** *"We use move semantics (`std::move`) when passing `PacketJob` structures through thread-safe bounded queues (`ThreadSafeQueue`). Instead of duplicating raw packet byte buffers, vectors transfer ownership. Payload references use offsets rather than raw pointers to avoid dangling pointer issues during memory reallocation."*

### Q2: Why use `std::mutex` instead of `std::shared_mutex`?
> **Answer:** *"While read-write locks (`std::shared_mutex`) sound ideal for read-heavy rule checking, winpthreads implementations on Windows MinGW GCC have known runtime assertion failures (`lock_shared`). Replacing it with `std::mutex` and lightweight `std::lock_guard` provided 100% cross-platform thread stability across Windows, Linux, and macOS."*

### Q3: What is the difference between TCP and UDP in your packet parser?
> **Answer:** *"TCP is a stateful, connection-oriented protocol with variable-length headers (20-60 bytes depending on options like TCP timestamps/SACK) and flags (SYN, ACK, FIN, RST). UDP is stateless with a fixed 8-byte header containing source port, dest port, length, and checksum."*

### Q4: How does your engine block an application?
> **Answer:** *"We block at the flow level. When the first `TLS Client Hello` packet arrives, we extract the SNI. If the SNI matches a blocked app (e.g. YouTube), we mark that 5-tuple flow state as `BLOCKED`. All subsequent data packets for that flow are dropped immediately without needing deep inspection again."*

---

## 🏆 Summary Checklist for Your Interview

- [x] Know the 5-tuple: **Src IP, Dst IP, Src Port, Dst Port, Protocol**
- [x] Know TLS Client Hello SNI extension: **Record 0x16, Handshake 0x01, Extension 0x0000**
- [x] Know the pipeline: **Reader -> LB Threads -> FP Threads -> Output Writer**
- [x] Know the thread balance fix: **Bit-shifting hash `(hash >> 16) % num_fps`**
- [x] Web stack: **Node.js, Express, Chart.js, Vanilla CSS Glassmorphism**
