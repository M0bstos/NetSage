# NetSage Integration Guide

This guide provides instructions for frontend developers and n8n workflow developers on how to integrate with the NetSage backend system.

## 🚀 System Overview

NetSage backend implements a complete pipeline for:
1. URL submission and scanning
2. Data processing and cleaning
3. Report generation with AI
4. Real-time status updates

The system uses WebSockets for real-time updates and a state machine for tracking scan progress through the following states:
- `pending` → `scanning` → `processing` → `generating_report` → `completed`
- `failed` (can occur at any stage)

## 📋 For Frontend Developers

### REST API Endpoints

#### 1. Submit a new scan
```
POST /api/scan
```
Request body:
```json
{
  "website_url": "https://example.com"
}
```
Response:
```json
{
  "success": true,
  "message": "Scan request created successfully",
  "requestId": "uuid-of-the-scan"
}
```

#### 2. Get scan report
```
GET /api/report/:requestId
```
Response (in progress):
```json
{
  "success": true,
  "status": "processing",
  "message": "Scan data is being processed",
  "requestId": "uuid-of-the-scan"
}
```
Response (completed):
```json
{
  "success": true,
  "status": "completed",
  "results": [
    {
      "target": "example.com",
      "port": 80,
      "service": "http",
      "product": "nginx",
      "version": "1.18.0",
      "report": "Full cybersecurity analysis report..."
    }
  ],
  "requestId": "uuid-of-the-scan"
}
```

#### 3. Get scan status (for non-WebSocket clients)
```
GET /api/scan-status/:requestId
```
Response:
```json
{
  "success": true,
  "requestId": "uuid-of-the-scan",
  "status": "scanning"
}
```

#### 4. Retry failed scan
```
POST /api/retry-scan/:requestId
```
Response:
```json
{
  "success": true,
  "message": "Scan retry initiated",
  "requestId": "uuid-of-the-scan"
}
```

### WebSocket Integration

For real-time updates, connect to the WebSocket server:

1. **Connect to the WebSocket server**
```javascript
// Using Socket.IO client
const socket = io('http://localhost:4000');

socket.on('connect', () => {
  console.log('Connected to WebSocket server');
});
```

2. **Subscribe to scan updates**
```javascript
// Subscribe to updates for a specific scan
socket.emit('subscribe', requestId);

// Listen for scan updates
socket.on('scanUpdate', (data) => {
  console.log(`Scan ${data.requestId} status: ${data.status}`);
  // data contains: requestId, status, previousStatus, timestamp
});
```

3. **Unsubscribe when no longer needed**
```javascript
socket.emit('unsubscribe', requestId);
```

4. **Listen for system notifications**
```javascript
socket.on('notification', (data) => {
  console.log(`${data.type}: ${data.message}`);
  // data contains: message, type (info/warning/error), timestamp
});
```

### Example Implementation

A simple test client is available at `backend/test-client/index.html` that demonstrates:
- Connecting to WebSocket
- Submitting scans
- Receiving real-time updates

## 🔄 For n8n Workflow Developers

### Webhook Integration Points

#### 1. Scan Trigger
When a new scan is submitted, the backend will make a POST request to your n8n webhook with:

```json
{
  "requestId": "uuid-of-the-scan",
  "website_url": "https://example.com"
}
```

You should configure this webhook URL in the `.env` file:
```
N8N_WEBHOOK_URL=your_n8n_webhook_url_here
```

#### 2. Submit Scan Results
After completing the scan, your n8n workflow should POST the results to:
```
POST /webhooks/scan-result
```

Request body:
```json
{
  "request_id": "uuid-of-the-scan",
  "scan_data": {
    // Raw scan data in any format
    // The backend will extract and process the data
  }
}
```

Example payload structure:
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "scan_data": {
    "target": "example.com",
    "ports": [
      {
        "port": 80,
        "protocol": "tcp",
        "service": {
          "name": "http",
          "product": "nginx",
          "version": "1.18.0"
        }
      },
      {
        "port": 443,
        "protocol": "tcp",
        "service": {
          "name": "https",
          "product": "nginx",
          "version": "1.18.0"
        }
      }
    ]
  }
}
```

#### 3. Optional: Trigger Data Processing
If you need to manually trigger data processing:
```
POST /webhooks/process-trigger
```

Request body (optional, to process a specific request):
```json
{
  "request_id": "uuid-of-the-scan"
}
```

### Important Notes for n8n Developers

1. The backend will automatically update the scan state to `processing` when it receives scan results from n8n.
2. All raw scan data is stored as-is in the database before processing.
3. The backend will automatically process scan results after receiving them.
4. You can monitor the state transitions via WebSocket for debugging.

## 🖥️ Getting Started

### Server Configuration

1. Set up environment variables in `.env`:
```
DATABASE_URL=postgresql://<user>:<password>@<host>:<port>/<db>?sslmode=require
GROQ_API_KEY=your_groq_api_key_here
N8N_WEBHOOK_URL=your_n8n_webhook_url_here
PORT=4000
```

2. Start the server:
```
cd backend
npm install
npm run dev
```

### Testing

1. Use the test client:
   - Open `backend/test-client/index.html` in a browser
   - Connect to WebSocket server
   - Submit a scan and monitor progress

2. Use API testing tools like Postman:
   - Send requests to the API endpoints
   - Test webhook endpoints with sample payloads

## 🔄 State Transition Flow

The complete state transition flow is:

1. `pending` - Initial state when scan is submitted
2. `scanning` - When n8n starts scanning the target
3. `processing` - When scan results are received and being processed
4. `generating_report` - When AI report generation starts
5. `completed` - When the full process is complete
6. `failed` - If any step fails (can transition from any state)

## 📊 Database Schema

For reference, here's the database schema:

- **scan_requests**: Stores scan requests with status
  - `id (UUID)`, `website_url (TEXT)`, `status (TEXT)`, `created_at (TIMESTAMP)`

- **raw_scan_data**: Stores raw JSON data from n8n
  - `id (UUID)`, `request_id (UUID)`, `raw_json (JSONB)`, `created_at (TIMESTAMP)`

- **scan_results**: Stores cleaned and processed scan results with reports
  - `id (UUID)`, `request_id (UUID)`, `target`, `port`, `service`, `product`, `version`, `report (TEXT)`, `created_at (TIMESTAMP)`

---

For any questions or issues, please contact the backend development team.
