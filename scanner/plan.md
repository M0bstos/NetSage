# Website Scanner Implementation Plan

This document outlines the step-by-step plan for implementing a basic website security scanner that will replace the n8n workflow while maintaining compatibility with the existing NetSage backend.

## 1. Setup Project Structure and Dependencies

- [x] Initialize NPM project in the scanner directory
- [x] Install core dependencies
  - `express` - For webhook endpoint
  - `node-nmap` - For port and service scanning
  - `axios` - For HTTP requests and header analysis
  - `dotenv` - For environment variables
- [x] Setup basic directory structure
- [x] Create environment configuration template
- [x] Add .gitignore file

```bash
npm init -y
npm install express node-nmap axios dotenv
```

## 2. Create Core Scanner Module

- [x] Create scanner core module (`scanner/lib/scanner.js`)
  - [x] Implement basic port scanning functionality
  - [x] Implement service detection
  - [x] Implement version detection where possible
  - [x] Add HTTP header analysis for web servers
  - [x] Implement output formatting to match expected JSON structure
  - [x] Add error handling and timeout management
- [x] Create test utility for scanner module (`scanner/test/test-scanner.js`)

## 3. Create Webhook Interface

- [x] Create Express server for webhook endpoints (`scanner/index.js`)
  - [x] Implement endpoint to receive scan requests
  - [x] Parse incoming request parameters (URL, requestId)
  - [x] Trigger scanning process
  - [x] Implement callback to send results back to main backend
  - [x] Add status tracking endpoints
- [x] Create test client for manual testing (`scanner/test/client/index.html`)
- [x] Implement CORS configuration for cross-origin requests
- [x] Create enhanced testing tools for API validation
  - [x] Direct test HTML interface (`direct-test.html`)
  - [x] Simple HTTP server for test client (`direct-server.js`)
  - [x] Convenience script to run test environment (`run-test-servers.ps1`)

## 4. Create Result Formatter

- [x] Create formatter module (integrated in `scanner/index.js`)
  - [x] Implement JSON output formatter compatible with existing backend
  - [x] Format scan results to match expected structure:
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
        }
      ]
    }
    ```
  - [ ] Add severity assessment logic
  - [x] Format service and version information
  - [x] Generate consistent port entries

Note: Instead of creating a separate formatter module, we integrated the formatting functionality directly into the index.js file with the `formatResultsForBackend` function. This simplifies the architecture while still providing the same functionality.

## 5. Implement Configuration and Environment

- [x] Create configuration module (integrated in `.env` and `index.js`)
  - [x] Set up scanning parameters (timeout, ports to scan)
  - [x] Configure callback URL for results
  - [x] Set up scan depth options
- [x] Create .env template with required variables

Note: Instead of creating a separate configuration module, we integrated the configuration directly into the environment variables and the main application. This approach simplifies the codebase while still providing flexible configuration options.

## 6. Add Testing Utilities

- [ ] Create test script for local scanning (`scanner/test/local-scan.js`)
  - [ ] Add command-line interface for testing
  - [ ] Implement simple output display
  - [ ] Add option to save results to file

## 7. Integrate with Main Backend

- [x] Update scanner service to communicate with the main backend
  - [x] Configure correct callback URL for the backend's webhook endpoint
  - [x] Ensure scanner callbacks use the proper webhook format
  - [x] Match the backend's expected JSON structure for scan results

## 8. Add Documentation

- [x] Create README with setup and usage instructions
- [x] Document output format and compatibility notes
- [ ] Add architectural diagram

## 9. Testing

- [x] Test scanning against various website types
  - [x] Static websites (tested with scanme.nmap.org)
  - [ ] Dynamic web applications
  - [ ] Secured vs. unsecured sites
- [x] Test integration with main backend
  - [x] Update backend to use scanner instead of n8n
  - [x] Fix backend API calls to use axios instead of fetch
  - [x] Configure proper communication between frontend, backend and scanner
  - [x] Fix data processing in webhook controller
  - [x] Test full end-to-end workflow
- [ ] Test error handling scenarios
  - [ ] Unreachable hosts
  - [ ] Timeout conditions
  - [ ] Malformed URLs

## 10. Optional Enhancements

- [ ] Add caching layer for repeat scans
- [ ] Implement concurrent scanning for faster results
- [ ] Add more detailed TLS/SSL analysis
- [ ] Implement basic vulnerability matching against known CVEs
