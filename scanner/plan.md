# Website Scanner Implementation Plan

This document outlines the step-by-step plan for implementing a basic website security scanner that will replace the n8n workflow while maintaining compatibility with the existing NetSage backend.

## 1. Setup Project Structure and Dependencies

- [ ] Initialize NPM project in the scanner directory
- [ ] Install core dependencies
  - `express` - For webhook endpoint
  - `node-nmap` - For port and service scanning
  - `axios` - For HTTP requests and header analysis
  - `dotenv` - For environment variables

```bash
npm init -y
npm install express node-nmap axios dotenv
```

## 2. Create Core Scanner Module

- [ ] Create scanner core module (`scanner/lib/scanner.js`)
  - [ ] Implement basic port scanning functionality
  - [ ] Implement service detection
  - [ ] Implement version detection where possible
  - [ ] Add HTTP header analysis for web servers
  - [ ] Implement output formatting to match expected JSON structure
  - [ ] Add error handling and timeout management

## 3. Create Webhook Interface

- [ ] Create Express server for webhook endpoints (`scanner/index.js`)
  - [ ] Implement endpoint to receive scan requests
  - [ ] Parse incoming request parameters (URL, requestId)
  - [ ] Trigger scanning process
  - [ ] Implement callback to send results back to main backend

## 4. Create Result Formatter

- [ ] Create formatter module (`scanner/lib/formatter.js`)
  - [ ] Implement JSON output formatter compatible with existing backend
  - [ ] Add severity assessment logic
  - [ ] Format service and version information
  - [ ] Generate consistent port entries

## 5. Implement Configuration and Environment

- [ ] Create configuration module (`scanner/config.js`)
  - [ ] Set up scanning parameters (timeout, ports to scan)
  - [ ] Configure callback URL for results
  - [ ] Set up scan depth options
- [ ] Create .env template with required variables

## 6. Add Testing Utilities

- [ ] Create test script for local scanning (`scanner/test/local-scan.js`)
  - [ ] Add command-line interface for testing
  - [ ] Implement simple output display
  - [ ] Add option to save results to file

## 7. Integrate with Main Backend

- [ ] Update main backend to call scanner service instead of n8n
  - [ ] Point `N8N_WEBHOOK_URL` to scanner service
  - [ ] Ensure scanner callbacks use the proper webhook format

## 8. Add Documentation

- [ ] Create README with setup and usage instructions
- [ ] Document output format and compatibility notes
- [ ] Add architectural diagram

## 9. Testing

- [ ] Test scanning against various website types
  - [ ] Static websites
  - [ ] Dynamic web applications
  - [ ] Secured vs. unsecured sites
- [ ] Test integration with main backend
- [ ] Test error handling scenarios
  - [ ] Unreachable hosts
  - [ ] Timeout conditions
  - [ ] Malformed URLs

## 10. Optional Enhancements

- [ ] Add caching layer for repeat scans
- [ ] Implement concurrent scanning for faster results
- [ ] Add more detailed TLS/SSL analysis
- [ ] Implement basic vulnerability matching against known CVEs
