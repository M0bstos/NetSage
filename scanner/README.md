# NetSage Scanner

The NetSage Scanner is a comprehensive web security scanning tool that integrates Nmap port scanning and Nuclei vulnerability scanning into a unified API service.

## Features

- **Port Scanning**: Detects open ports and services using Nmap
- **HTTP Header Analysis**: Examines HTTP headers for security issues
- **Vulnerability Scanning**: Uses Nuclei to identify security vulnerabilities
- **Technology Detection**: Identifies web technologies, frameworks, and servers
- **REST API**: Simple endpoints to submit and retrieve scan results
- **Webhook Integration**: Sends results back to a callback URL
- **Result Storage**: Stores scan results for future reference
- **Comprehensive Scans**: Options for standard or in-depth scanning

## Prerequisites

- Node.js v16 or higher
- npm or yarn package manager
- Nmap network scanner
- Nuclei vulnerability scanner (highly recommended)

## Nmap Installation

The scanner requires Nmap to be installed on your system. Here's how to install it:

### Windows

1. Download the latest Nmap installer from [nmap.org](https://nmap.org/download.html)
2. Run the installer and follow the installation instructions
3. Make sure to include Npcap during installation
4. Add Nmap to your system PATH if not added automatically

### macOS

Using Homebrew:
```
brew install nmap
```

### Linux (Ubuntu/Debian)

```
sudo apt-get update
sudo apt-get install nmap
```

### Linux (Fedora/RHEL/CentOS)

```
sudo dnf install nmap
```

## Verifying Nmap Installation

After installation, verify Nmap is correctly installed by running:
```
nmap --version
```

## Nuclei Installation (Optional)

For enhanced vulnerability scanning, you can install Nuclei:

### Windows

1. Download the latest Nuclei release from [GitHub](https://github.com/projectdiscovery/nuclei/releases)
2. Extract the ZIP file and add the directory to your system PATH
3. Run nuclei to download the default templates: `nuclei -update-templates`

### macOS

Using Homebrew:
```
brew install nuclei
nuclei -update-templates
```

### Linux

```
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
nuclei -update-templates
```

## Verifying Nuclei Installation

After installation, verify Nuclei is correctly installed by running:
```
nuclei -version
```

## API Endpoints

The scanner provides the following REST API endpoints:

### Health Check
```
GET /health
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
| `HOST` | Host address to bind | `0.0.0.0` |
| `CALLBACK_URL` | URL to send scan results to | `http://localhost:3000/api/webhook/scan-result` |
| `DEFAULT_SCAN_TIMEOUT` | Default timeout for standard scans (ms) | `300000` (5 minutes) |
| `COMPREHENSIVE_SCAN_TIMEOUT` | Timeout for comprehensive scans (ms) | `600000` (10 minutes) |
| `DEFAULT_PORTS_TO_SCAN` | Comma-separated list of ports to scan | `21,22,25,80,443,3306,8080,8443` |
| `ENABLE_NUCLEI` | Whether to enable Nuclei scanning | `true` |
| `NUCLEI_PATH` | Path to the Nuclei executable | `nuclei` |
| `NUCLEI_TEMPLATES` | Comma-separated list of templates | `technologies,cves` |
| `COMPREHENSIVE_SCAN` | Run scans with more templates | `false` |
| `AGGRESSIVE_SCAN` | Use more aggressive scanning techniques | `false` |

## Setup and Usage

1. Clone the repository
2. Install dependencies:
```
npm install
```

3. Configure environment variables (create a `.env` file):
```
PORT=3001
HOST=0.0.0.0
CALLBACK_URL=http://localhost:3000/api/webhook/scan-result
ENABLE_NUCLEI=true
```

4. Start the scanner:
```
node index.js
```

## Testing the Scanner

Run the included test script to verify the scanner functionality:

```
node test/test-scanner-enhanced.js
```

This will perform a comprehensive scan against a test target and display the results.

## Result Format

The scan results include:

- Target URL/domain
- Open ports and services
- HTTP header analysis
- Detected technologies
- Vulnerability findings (with Nuclei)
  - Severity levels (critical, high, medium, low, info)
  - Vulnerability names and descriptions
  - References and affected URLs

## Configuration

1. Copy `.env.example` to `.env`
2. Adjust settings in the `.env` file according to your environment

### Nuclei Configuration Options

To enable and configure Nuclei vulnerability scanning, add these settings to your `.env` file:

```
# Nuclei integration
ENABLE_NUCLEI=true
NUCLEI_PATH=nuclei
NUCLEI_TEMPLATES=cves,vulnerabilities,technologies
NUCLEI_OUTPUT_DIR=./scan-results
```

- `ENABLE_NUCLEI`: Set to 'true' to enable Nuclei scanning, 'false' to disable
- `NUCLEI_PATH`: Path to the Nuclei executable (default: 'nuclei')
- `NUCLEI_TEMPLATES`: Comma-separated list of template categories to use
- `NUCLEI_OUTPUT_DIR`: Directory to store scan results (default: './scan-results')

## Running the Scanner

After installing dependencies with `npm install`, you have several options to run and test the scanner:

### Core Scanner Testing

Test the core scanner module directly:

```
node test/test-scanner.js example.com
```

### Running the Webhook Server

Start the webhook server that listens for scan requests:

```
npm start
```

Or for development with auto-reload:

```
npm run dev
```

### Testing Tools

For testing the full scanning workflow, we provide several testing tools:

1. **Test Client**: A web-based interface for testing the scanner API
   - Located at `test/client/index.html`
   - Start with `node test/server.js`

2. **Direct Test Interface**: A simpler testing interface
   - Located at `direct-test.html`
   - Start with `node direct-server.js`

3. **Combined Test Environment**: Use the PowerShell script to start both servers:
   - Run `.\run-test-servers.ps1`
   - Access the scanner API at http://localhost:3001
   - Access the direct test interface at http://localhost:8090

## Integration with Backend

This scanner is designed to replace the n8n workflow in the NetSage system. It:
1. Provides a webhook endpoint to receive scan requests
2. Performs port scanning and service detection using Nmap
3. Analyzes HTTP headers and security configurations
4. Returns results in a format compatible with the NetSage backend

## Expected Output Format

The scanner will return results in the following format:

```json
{
  "request_id": "uuid-of-the-scan",
  "scan_data": [
    {
      "target": "example.com",
      "port": 80,
      "service": "http",
      "product": "nginx",
      "version": "1.18.0"
    },
    {
      "target": "example.com",
      "port": 443,
      "service": "https",
      "product": "nginx",
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
