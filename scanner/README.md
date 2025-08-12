# NetSage Scanner

The NetSage Scanner is a comprehensive web security scanning tool that integrates port scanning and vulnerability detection into a unified API service.

## Features

- **Port Scanning**: Detects open ports and services
- **HTTP Header Analysis**: Examines HTTP headers for security issues
- **Vulnerability Scanning**: Identifies security vulnerabilities
- **Technology Detection**: Identifies web technologies, frameworks, and servers
- **REST API**: Simple endpoints to submit and retrieve scan results
- **Webhook Integration**: Sends results back to a callback URL
- **Result Storage**: Stores scan results for future reference
- **Proxy Support**: Rotate through proxies for stealth scanning

## Quick Start

1. Clone the repository
2. Run `npm install`
3. Create a `.env` file based on `.env.example`
4. Run `npm start`

## Prerequisites

- Node.js v16 or higher
- npm or yarn package manager
- Nmap network scanner
- Nuclei vulnerability scanner (optional but recommended)

## Installation

### Install Dependencies

```bash
npm install
```

### Configure Environment

Copy the example environment file and modify as needed:

```bash
cp .env.example .env
```

### Nmap Installation

The scanner requires Nmap to be installed on your system:

- **Windows**: Download from [nmap.org](https://nmap.org/download.html) and include Npcap
- **macOS**: `brew install nmap`
- **Linux (Ubuntu/Debian)**: `sudo apt-get install nmap`
- **Linux (Fedora/RHEL/CentOS)**: `sudo dnf install nmap`

Verify installation with: `nmap --version`

### Nuclei Installation (Optional)

For enhanced vulnerability scanning:

- **Windows**: Download from [GitHub](https://github.com/projectdiscovery/nuclei/releases)
- **macOS**: `brew install nuclei`
- **Linux**: `GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`

After installation: `nuclei -update-templates`

## Getting Started with Proxies

### Why Use Proxies?

Using proxies with the NetSage Scanner provides several benefits:
- **Anonymity**: Hide your real IP address when scanning targets
- **Avoid IP blocks**: Prevent your IP from being blocked due to frequent scans
- **Geographic distribution**: Test from different locations around the world
- **Increased success rate**: Bypass restrictions that might block direct connections

### Step-by-Step Proxy Setup

1. **Obtain a Proxy**
   - **Purchase a Proxy**: Services like Bright Data, Oxylabs, or SmartProxy offer reliable proxies
   - **Use a Free Proxy**: Free proxies are available but often less reliable
   - **Self-host a Proxy**: Set up your own proxy server using Squid or NGINX

2. **Configure Your Proxy**
   - Create or edit your `.env` file in the scanner directory:
     ```bash
     cp .env.example .env
     ```
   - Enable proxy support and add your proxy details:
     ```bash
     # Enable proxy support
     ENABLE_PROXY_SUPPORT=true
     ROTATE_USER_AGENTS=true
     ENABLE_CONNECTION_POOLING=true
     
     # Add your proxy details (replace with your actual proxy information)
     PROXY_LIST='[{"protocol":"http","host":"your-proxy-address.com","port":8080}]'
     ```

3. **Test Your Proxy Configuration**
   - Run the included test script:
     ```bash
     node test-proxy.js
     ```
   - Verify the script shows "Proxy test successful!" and displays the proxy's IP

### Proxy Types Supported

- **HTTP Proxy**: Most common type
  ```bash
  PROXY_LIST='[{"protocol":"http","host":"proxy.example.com","port":8080}]'
  ```

- **HTTPS Proxy**: Encrypted proxy connection
  ```bash
  PROXY_LIST='[{"protocol":"https","host":"proxy.example.com","port":443}]'
  ```

- **SOCKS5 Proxy**: Supports TCP/UDP traffic
  ```bash
  PROXY_LIST='[{"protocol":"socks5","host":"proxy.example.com","port":1080}]'
  ```

- **Authenticated Proxy**: Proxy requiring username/password
  ```bash
  PROXY_LIST='[{"protocol":"http","host":"proxy.example.com","port":8080,"auth":{"username":"user","password":"pass"}}]'
  ```

- **TOR Network**: Anonymous routing network
  ```bash
  ENABLE_TOR=true
  # TOR must be running locally on port 9050
  ```

## API Endpoints

```
GET /health - Health check endpoint
POST /scan - Submit a new scan request
GET /status/:id - Check scan status
```
Returns the scanner's operational status.

### Scan Request
```
POST /scan
```
Submits a new scan request.

Request body:
```json
{
  "website_url": "example.com",
  "requestId": "optional-unique-id",
  "options": {
    "comprehensive": true,
    "aggressive": false
  }
}
```

Response:
```json
{
  "success": true,
  "message": "Scan request received and processing",
  "requestId": "generated-uuid",
  "estimatedTime": "1-3 minutes"
}
```

### Scan Status
```
GET /status/:requestId
```
Gets the current status of a scan.

Response:
```json
{
  "success": true,
  "requestId": "scan-uuid",
  "status": "scanning|sending|completed|failed",
  "target": "example.com",
  "scanType": "standard|comprehensive",
  "startTime": "2023-05-01T12:00:00Z",
  "completionTime": "2023-05-01T12:03:45Z",
  "elapsedTimeSeconds": 225,
  "estimatedTimeRemaining": "2 minutes",
  "findings": 3,
  "error": null,
  "resultsAvailable": true
}
```

### Get Results
```
GET /results/:requestId
```
Retrieves the full results of a completed scan.

### List Active Scans
```
GET /scans
```
Lists all active or recently completed scans.

## Environment Variables

Configure the scanner behavior using these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Port for the scanner server | `3001` |
| `HOST` | Host address to bind | `localhost` |
| `CALLBACK_URL` | URL to send scan results to | `http://localhost:3000/api/webhooks/scan-result` |
| `RESULTS_DIR` | Directory to store scan results | `scan-results` |
| `DEFAULT_SCAN_TIMEOUT` | Default timeout for standard scans (ms) | `30000` |
| `DEFAULT_PORTS_TO_SCAN` | Comma-separated list of ports to scan | `21,22,25,80,443,3306,8080,8443` |
| `ENABLE_NUCLEI` | Whether to enable Nuclei scanning | `true` |
| `NUCLEI_PATH` | Path to the Nuclei executable | `nuclei` |
| `ENABLE_PROXY_SUPPORT` | Whether to enable proxy support | `false` |
| `ENABLE_TOR` | Whether to enable TOR routing | `false` |
| `ROTATE_USER_AGENTS` | Whether to rotate user agents | `true` |
| `ENABLE_CONNECTION_POOLING` | Whether to enable connection pooling | `true` |
| `PROXY_LIST` | JSON array of proxy configurations | `[]` |

## Running the Scanner

Start the scanner:
```bash
npm start
```

For development with auto-reload:
```bash
npm run dev
```

## Sending a Scan Request

To test the scanner, send a request:

```bash
## Advanced Configuration

### High-Stealth Mode

For maximum stealth during scanning:

```bash
# .env configuration
ENABLE_PROXY_SUPPORT=true
ENABLE_TOR=true
ROTATE_USER_AGENTS=true
ENABLE_CONNECTION_POOLING=true
ENABLE_EVASION=true
EVASION_PROFILE=aggressive
```

### Proxy Types

The scanner supports different proxy types:
- HTTP proxies
- HTTPS proxies
- SOCKS5 proxies (including TOR)

### Using Environment Variables

For proxy configuration via environment variables:

```
# .env file
ENABLE_PROXY_SUPPORT=true
ROTATE_USER_AGENTS=true
PROXY_LIST='[{"protocol":"http","host":"proxy.example.com","port":8080}]'
```

### Testing Your Proxy

To verify your proxy is working correctly:

1. **Create a Simple Test Script**
   - Create a file named `test-proxy.js` with the following content:

```javascript
require('dotenv').config();
const axios = require('axios');

async function testProxy() {
  const proxyConfig = JSON.parse(process.env.PROXY_LIST || '[]')[0];
  
  if (!proxyConfig) {
    console.error('No proxy configured in PROXY_LIST environment variable');
    return;
  }
  
  console.log(`Testing proxy: ${proxyConfig.protocol}://${proxyConfig.host}:${proxyConfig.port}`);
  
  try {
    const response = await axios({
      method: 'get',
      url: 'http://httpbin.org/ip',
      proxy: {
        host: proxyConfig.host,
        port: proxyConfig.port,
        protocol: proxyConfig.protocol,
        ...(proxyConfig.auth && { auth: proxyConfig.auth })
      },
      timeout: 10000
    });
    
    console.log('Proxy test successful!');
    console.log('Your IP appears as:', response.data.origin);
  } catch (error) {
    console.error('Proxy test failed:', error.message);
  }
}

testProxy();
```

2. **Run the Test Script**
```bash
node test-proxy.js
```

### Troubleshooting Proxies

Common proxy issues and solutions:

- **Connection Failed**: 
  - Check if your proxy server is online and accessible
  - Verify that your network allows connections to the proxy server
  - Ensure the proxy address and port are correct

- **Authentication Error**: 
  - Double-check your username and password
  - Ensure special characters in passwords are properly escaped in the .env file

- **Slow Performance**: 
  - Add these settings to your .env file:
    ```
    ENABLE_CONNECTION_POOLING=true
    MAX_POOL_SIZE=10
    POOL_TIMEOUT=30000
    ```

- **TOR Not Working**: 
  - Verify TOR service is running with: `netstat -an | findstr 9050`
  - Install TOR if needed: https://www.torproject.org/download/

## Output Format

The scanner produces a JSON output with the following structure:

```json
{
  "request_id": "uuid-here",
  "scan_data": [
    {
      "host": "example.com",
      "ip": "93.184.216.34",
      "ports": [
        {
          "port": 80,
          "protocol": "tcp",
          "service": "http",
          "state": "open"
        },
        {
          "port": 443,
          "protocol": "tcp",
          "service": "https",
          "state": "open"
        }
      ],
      "http_headers": {
        "server": "ECS (dcb/7F84)",
        "content-type": "text/html",
        "x-frame-options": "DENY"
      },
      "security_issues": [
        {
          "type": "missing_header",
          "name": "Content-Security-Policy",
          "severity": "medium",
          "description": "Content Security Policy header is missing"
        }
      ]
    }
  ],
  "scan_timestamp": "2023-05-01T15:45:30Z",
  "scan_duration_ms": 12500
}
```
```

## Customizing Scans

You can customize the scan behavior by modifying the request options:

```json
{
  "website_url": "example.com",
  "options": {
    "ports": "21,22,25,80,443,8080",
    "comprehensive": true,
    "aggressive": false,
    "timeout": 300000
  }
}
```

### Scan Options

- **ports**: Comma-separated list of ports to scan
- **comprehensive**: Run a more thorough scan with additional checks
- **aggressive**: Use more aggressive scanning techniques (may be more detectable)
- **timeout**: Maximum time in milliseconds before the scan aborts

## Project Structure

```
scanner/
├── .env                   # Environment configuration
├── index.js               # Main application entry point
├── package.json           # Node.js dependencies
├── proxy-manager.js       # Proxy rotation management
├── lib/                   # Core scanner modules
│   ├── scanner.js         # Main scanner implementation
│   ├── nuclei.js          # Nuclei integration
│   ├── portDetection.js   # Port scanning capabilities
│   └── utils/             # Utility functions
└── scan-results/          # Directory for storing results
```

## Security Considerations

- Always obtain proper authorization before scanning any website or server
- Be aware that aggressive scanning may trigger security systems
- Use proxies ethically and in compliance with proxy server policies
- Consider legal implications of security scanning activities

## Troubleshooting

### Scanner Won't Start

- Verify Node.js is installed correctly (v16+)
- Check if the specified port is already in use
- Make sure environment variables are set correctly

### Scan Results Empty

- Verify target is online and reachable
- Check if any firewalls are blocking scan traffic
- Ensure Nmap is installed and in your PATH

### Nuclei Not Working

- Make sure Nuclei is installed and in your PATH
- Run `nuclei -update-templates` to update templates
- Try running Nuclei manually to verify it works

## License

This project is licensed under the ISC License.
      "version": "1.18.0"
    }
  ],
  "vulnerabilities": [
    {
      "target": "example.com",
      "name": "Outdated jQuery Version",
      "severity": "medium",
      "type": "technology",
      "description": "The site is using an outdated version of jQuery library which may contain known security vulnerabilities.",
      "matched": "http://example.com/js/jquery.min.js",
      "cves": ["CVE-2020-11022", "CVE-2020-11023"],
      "references": ["https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/"],
      "tags": ["jquery", "outdated", "javascript"]
    }
  ]
}
```

## Troubleshooting

### NMAP Issues

If you get an error "NMAP not found at command location: nmap", make sure:
1. Nmap is correctly installed
2. Nmap is accessible from your PATH

### Nuclei Issues

If Nuclei scanning is enabled but not working:

1. Verify Nuclei is installed: `nuclei -version`
2. Check that templates are installed: `ls -la ~/.nuclei-templates`
3. Make sure the `NUCLEI_PATH` in `.env` points to the correct location
4. Try running Nuclei manually to verify it works:
   ```
   nuclei -u https://example.com -t cves -silent
   ```
5. Examine the scanner logs for specific error messages related to Nuclei

### CORS Issues

If you encounter CORS errors when testing the API:
1. Ensure the server is running on the expected port (default: 3001)
2. Check that the client is using the correct URL to connect to the server
3. For testing with a browser file:// URL, use one of our provided HTTP servers:
   - `node direct-server.js` for the direct test interface
   - `node test/server.js` for the test client

### Connection Issues

If you're having trouble connecting to the scanner API:
1. Verify the server is running with `npm start`
2. Check the server logs for any errors
3. Use the "Test Connection" button in the direct test interface to test connectivity
4. Ensure there are no firewalls blocking the connection on port 3001
3. You may need to specify the Nmap location in the scanner.js file by uncommenting and updating this line:
   ```javascript
   // nmap.nmapLocation = 'path/to/nmap';
   ```
