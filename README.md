# Yes-U: AI-Powered Website Vulnerability Scanner 🚨🧠

Yes-U is an intelligent **AI-driven Website Vulnerability Scanner and Analyzer**, built using **React.js** on the frontend and a **custom PHP API** on the backend. It leverages **OpenAI’s GPT-4o** model to provide automated, human-like vulnerability assessments and detailed security reports for any publicly accessible website.

## 🌐 What This Project Does

- 🕷️ **Scans Websites for Vulnerabilities** like:
  - Open Ports
  - SSL Certificate issues
  - Missing HTTP Security Headers
  - SQL Injection Risks
  - XSS (Cross Site Scripting) Injection
  - Remote Shell Upload Exposure
  - Weak Cookies and Tech Stack Exposure

- 🔐 **Integrates APIs**:
  - Shodan
  - SSL Labs
  - IPInfo
  - SecurityHeaders.com

- 🤖 **Uses OpenAI GPT-4o** to:
  - Analyze raw scan data
  - Generate clean, readable security reports
  - Provide risk scoring and severity ranking
  - Offer remediation suggestions

- 📊 **Beautiful Dashboard** built with **React + Vite**:
  - Displays security results in real-time
  - Provides scorecards and risk tags
  - Allows export as **PDF** or **JSON**

---

## 💡 Tech Stack

| Layer         | Tech Used                         |
|---------------|-----------------------------------|
| Frontend      | React.js + Vite + Tailwind CSS    |
| Backend       | PHP (cURL, OpenSSL, sockets)      |
| AI Engine     | OpenAI GPT-4o API                 |
| External APIs | Shodan, SSL Labs, IPInfo, SecurityHeaders |
| Export        | JSON, PDFMake                     |

---

## 🧪 Getting Started

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react/README.md) uses [Babel](https://babeljs.io/) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

---

## ⚠️ Note

For production usage, it's recommended to enable **type-aware lint rules** and adopt **TypeScript**. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io).

---

## 👨‍💻 Built With Love by Team Yes-U

- **Ahimsa GMS**
- **Lilla Vinoth**
- **Gokul KP**
- **Kiran KP**
