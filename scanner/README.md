# NetSage Scanner Setup

This document provides instructions for setting up the NetSage website scanner.

## Prerequisites

- Node.js v14 or higher
- npm or yarn package manager
- Nmap network scanner

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

## Configuration

1. Copy `.env.example` to `.env`
2. Adjust settings in the `.env` file according to your environment

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
  ]
}
```

## Troubleshooting

### NMAP Issues

If you get an error "NMAP not found at command location: nmap", make sure:
1. Nmap is correctly installed
2. Nmap is accessible from your PATH

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
