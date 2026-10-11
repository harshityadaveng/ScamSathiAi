# ScamSathi AI 🛡️ — Cyber Fraud Screening & Verification Platform

ScamSathi AI is an Indian digital safety assistant designed to screen suspicious SMS, WhatsApp messages, URLs, websites, screenshots, and UPI payment requests for fraudulent intent, brand impersonation, and phishing threats.

---

## ✨ Features

- **Multi-Engine Message Screening**: Heuristic detection + Gemini AI model for Indian cyber fraud patterns (Utility disconnection threats, Banking KYC threats, Digital arrest, Fake jobs, Lottery/customs scams, and UPI collect fraud).
- **Evidence-Based Website Intelligence Pipeline**:
  - Live DNS record resolution (A, AAAA, MX, NS) with strict SSRF protection.
  - Multi-hop redirect chain tracing with loop detection and private IP blocking.
  - Domain registration intelligence via RDAP (creation date, age, registrar).
  - TLS/SSL certificate verification (expiration, self-signed detection).
  - External threat intelligence adapters (Google Web Risk, Google Safe Browsing v4, VirusTotal v3).
  - Brand lookalike, homoglyph, and typosquatting detection for 30+ major Indian banks and services.
- **In-Memory Screenshot & QR Scanner**: Decodes UPI payment requests, warns on malicious debit traps, and extracts text via OCR without persisting files to disk.
- **Bilingual Interface**: Full support for English and Hindi (हिन्दी).

---

## 🏗️ Architecture

- **Frontend**: React 18, Vite, Vanilla CSS design system, Lucide icons.
- **Backend**: Node.js, Express, Zod validation schemas, Google GenAI SDK.

```
ScamSathi AI/
├── src/                # React Frontend (Vite)
│   ├── components/     # UI components (Hero, Search, Modals, Cards)
│   ├── services/       # Frontend API client (api.js)
│   └── index.css       # Design tokens & styling
├── server/             # Express Backend
│   ├── src/
│   │   ├── controllers/# Route controllers (analyze, url, health, image)
│   │   ├── services/   # Intelligence pipelines (dns, tls, rdap, reputation, heuristics)
│   │   ├── middleware/ # Error handling, rate limiting, SSRF guard
│   │   └── validators/ # Zod request schemas
│   └── tests/          # Node test suite (120+ unit and integration tests)
├── .env.example        # Frontend environment template
└── package.json        # Root scripts
```

---

## 🚀 Getting Started

### 1. Prerequisites
- **Node.js** v18+ (tested on v20 and v24)
- **npm** v9+

### 2. Installation
Install dependencies for both frontend and backend:

```bash
# Install frontend dependencies
npm install

# Install backend dependencies
cd server
npm install
cd ..
```

### 3. Environment Setup

#### Frontend Configuration (`.env`)
Create a `.env` file in the root folder:
```env
VITE_API_BASE_URL=http://localhost:5000
```

#### Backend Configuration (`server/.env`)
Create a `.env` file in the `server/` folder:
```env
PORT=5000
NODE_ENV=development
CLIENT_URL=http://localhost:5173

# Rate Limiting
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_REQUESTS=30

# Gemini AI Integration (Optional)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-3.5-flash
AI_ENABLED=true

# Threat Intelligence (Optional)
URL_REPUTATION_PROVIDER=none # options: none | google_web_risk | google_safe_browsing | virustotal
```

---

## 🏃 Running Locally

Run both frontend and backend in separate terminal windows:

```bash
# Terminal 1: Start Frontend (Vite)
npm run dev
# Running on http://localhost:5173

# Terminal 2: Start Backend (Express API)
npm run server
# Running on http://localhost:5000
```

---

## 🧪 Running Tests

```bash
# Run server test suite
npm run test:server

# Build production frontend
npm run build
```

---

## 🛡️ Security & Privacy Notice

- Uploaded screenshots are inspected strictly in volatile memory and are never saved to disk.
- Sensitive parameters in URLs (tokens, passwords, session IDs) are automatically redacted before logging.
- Target websites are never scraped or rendered directly; all inspections are metadata and reputation queries with strict SSRF guards.
