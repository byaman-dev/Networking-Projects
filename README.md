# 🔍 NetRisk — Stage 1: The Scanning Engine

> Most port scanners tell you "port 22 is open." Cool. Now what?

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Stage](https://img.shields.io/badge/Stage-1%20of%205-orange?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Foundation%20Complete-success?style=for-the-badge)

---

## 🤔 What is NetRisk?

A port scanner is the "hello world" of network security projects — everyone builds one, most of them do the exact same thing: loop through some ports, print open/closed, done.

NetRisk is my attempt to build something closer to what a real tool would actually give you: not just *what's* open, but *why it matters*, laid out somewhere you'd actually want to look at it. It's being built in stages, on purpose, so each part is a real, working thing before the next layer goes on top:

1. **Scanning Engine** *(you are here)* — fast, safe, structured
2. **Risk & Explanation Layer** — every finding gets a plain-language "here's why this matters"
3. **Local Dashboard** — visual, one place, click to expand
4. **History Tracking** — how has my network's risk changed over time?
5. **Polished Local App** — a "Scan Now" button and live charts, running entirely on my own machine

This README covers Stage 1 only. Nothing here talks to the internet or looks pretty yet — it's the engine everything else depends on, so it needed to be solid first.

---

## ⚠️ The one rule this tool follows

**It refuses to scan anything except localhost or your own private network.** Not as a suggestion — it's an actual check in the code (`is_safe_target`), and it flatly declines to run against a public IP address.

Scanning something you don't own or don't have explicit permission to scan is illegal in most places. That's not a footnote — it's the whole reason this tool only ever points at `127.0.0.1` or addresses like `192.168.x.x`.

---

## ✨ What Stage 1 actually does

* 🧵 Scans multiple ports **concurrently** (threaded), instead of one-at-a-time like most beginner scanners
* 🧠 Classifies each port properly — not just open/closed, but the *reason*: refused, timed out, or an unexpected error, each with a plain-English explanation
* 🏷 Guesses the likely service behind a known port (SSH, HTTP, a Chromecast, a network printer...) from a curated list — not a brute-force scan of all 65535 ports, just the ones worth knowing about
* 📦 Outputs clean, structured **JSON** — not print statements — because Stage 3's dashboard needs to read this data, not parse scrollback

---

## 🧠 What building this taught me

* Real socket programming — `connect_ex`, timeouts, and the actual difference between "refused" and "filtered"
* Concurrency with `ThreadPoolExecutor` — why scanning 20 ports one-by-one is needlessly slow, and how threading fixes that without much extra code
* Designing data *for the next thing that reads it* — this JSON format isn't an afterthought, it's the actual contract Stage 2 and 3 depend on
* That "safe by design" isn't just a nice idea — it's a real function that runs before anything else does

---

## 📁 What's in the folder

```text
NetRisk - Stage 1 (Scanning Engine)
│
├── netrisk_scanner.py       → the engine
├── test_netrisk_scanner.py  → 15 tests, all green
├── README.md                → you are here
├── requirements.txt
└── sample_scan_results.json → example output from a real local scan
```

---

## ▶️ Running it

```bash
# scan your own machine using the default curated port list
python netrisk_scanner.py

# scan a specific range
python netrisk_scanner.py 127.0.0.1 --ports 1-1024

# scan a device on your home network (e.g. your router)
python netrisk_scanner.py 192.168.1.1
```

Try pointing it at a real public address, just to see the safety check in action:

```bash
python netrisk_scanner.py 8.8.8.8
```

```text
❌ Refusing to scan '8.8.8.8'.
NetRisk only scans localhost or addresses on your own private network...
```

---

## 🧪 Running the tests

```bash
python -m unittest test_netrisk_scanner.py -v
```

15 tests — mostly mocked sockets for speed and determinism, plus two real integration tests that actually open a live local socket to prove open/closed detection genuinely works, not just that the mocks are set up right.

---

## 💻 What the output looks like

```text
Scanning 127.0.0.1 (22 ports)...

Scan complete — 2 open port(s) found.
  22     SSH
  8080   HTTP (alternate)

Full results written to scan_results.json
```

And the JSON behind it (trimmed):

```json
{
  "target": "127.0.0.1",
  "scan_started": "2026-09-26T19:17:25Z",
  "scan_finished": "2026-09-26T19:17:25Z",
  "ports_scanned": 22,
  "results": [
    {
      "port": 22,
      "status": "open",
      "service_guess": "SSH",
      "detail": null,
      "checked_at": "2026-09-26T19:17:25Z"
    },
    {
      "port": 23,
      "status": "closed",
      "service_guess": "Telnet",
      "detail": "Connection refused (errno 111) — nothing is listening on this port.",
      "checked_at": "2026-09-26T19:17:25Z"
    }
  ]
}
```

Full example in `sample_scan_results.json`.

---

## 🚀 What's next — Stage 2

Right now, "port 23 is closed" and "port 22 is open" carry the same visual weight — no sense of *so what*. Stage 2 attaches a real risk level and plain-language explanation to every finding (why Telnet being open is a real problem, why an open SSH port isn't automatically bad, what to actually do about each one).

---

## 🌱 Honest reflection

The tempting version of this project is to skip straight to the dashboard — visuals are the fun part. I built the engine first anyway, because a beautiful dashboard reading garbage data is worse than a plain JSON file that's actually correct. Getting the classification logic right (open vs. closed vs. filtered vs. error, each with a real reason) turned out to be most of the actual thinking in this stage — the threading was almost the easy part.

---

## 📌 Quick facts

| Property        | Details                         |
| ---------------- | -------------------------------- |
| **Project**       | NetRisk                           |
| **Stage**         | 1 of 5 — Scanning Engine          |
| **Language**       | Python                            |
| **Tests**          | ✅ 15/15 passing                   |
| **Scope**          | Localhost / own private network only |

---

> *"A port scanner tells you what's open. This is the part where I made sure it tells the truth about it, too."*
