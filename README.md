# NetSage: Cybersecurity Scan and Report System

NetSage is a comprehensive tool for automated website security scanning and report generation. It features a state machine workflow, real-time updates via WebSockets, and AI-powered report generation.

## 🚀 Features

- **Automated Scanning Pipeline**: Submit a URL and get a complete security analysis
- **Real-time Status Updates**: WebSocket integration for live progress monitoring
- **AI-Powered Reports**: Generate readable cybersecurity reports with Groq LLM
- **Robust Architecture**: Clear separation between raw and processed data
- **Flexible Integration**: Well-documented API for frontend and n8n integration

## 📁 Project Structure

```
NetSage/
├── backend/               # Backend API and processing logic
│   ├── controllers/       # API controllers
│   ├── processors/        # Data processing scripts
│   ├── routes/            # API route definitions
│   ├── services/          # Core services (state machine, WebSocket)
│   ├── test-client/       # WebSocket test client
│   ├── .env.example       # Environment variables template
│   ├── db.js              # Database connection utilities
│   ├── index.js           # Main application entry point
│   └── package.json       # Node.js dependencies
├── integration-guide.md   # Guide for frontend and n8n integration
├── backend-dev-guide.md   # Backend developer quick reference
└── changes-log.md         # Development changelog
```

## 🛠️ Setup and Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/M0bstos/NetSage.git
   cd NetSage
   ```

2. Install backend dependencies:
   ```bash
   cd backend
   npm install
   ```

3. Create environment file:
   ```bash
   cp .env.example .env
   # Edit .env with your actual credentials
   ```

4. Start the server:
   ```bash
   npm run dev
   ```

5. Open the test client:
   ```
   backend/test-client/index.html
   ```

## 📋 Documentation

- **Integration Guide**: See [integration-guide.md](./integration-guide.md) for frontend and n8n integration details
- **Developer Guide**: See [backend-dev-guide.md](./backend-dev-guide.md) for implementation details and debugging
- **Architecture Updates**: See [updated-architecture.md](./docs/updated-architecture.md) for details on the new event-based processing
- **Testing Guide**: See [testing-guide.md](./docs/testing-guide.md) for information on how to test the system

## 🔄 Workflow

The system implements a state machine with the following flow:
- `pending` → `scanning` → `processing` → `generating_report` → `completed`
- `failed` (can occur at any stage)

## 👥 Contributors

- [Harsh Nanda :)](https://github.com/M0bstos) - Backend Development
- [Frontend Developer](https://github.com/RiddhiThakare) - Frontend Implementation
- [Param Shah <3](https://github.com/roaringspy) - n8n Integration

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
