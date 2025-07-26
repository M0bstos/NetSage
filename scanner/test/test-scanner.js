/**
 * Scanner Test Utility
 * 
 * Simple command-line utility to test the scanner functionality
 */

require('dotenv').config();
const Scanner = require('../lib/scanner');
const fs = require('fs');
const path = require('path');

// Parse command line arguments
const args = process.argv.slice(2);
const target = args[0];
const outputFile = args[1];

if (!target) {
  console.error('Usage: node test-scanner.js <target> [output-file]');
  console.error('Example: node test-scanner.js example.com results.json');
  process.exit(1);
}

// Create a scanner instance with settings from .env if available
const scanner = new Scanner({
  timeout: process.env.DEFAULT_SCAN_TIMEOUT || 30000,
  ports: process.env.DEFAULT_PORTS_TO_SCAN || '21,22,25,80,443,3306,8080,8443',
  aggressive: false
});

console.log(`Starting scan on target: ${target}`);
console.log('This may take a minute or two depending on the target...');

// Run the scan
scanner.scan(target)
  .then((results) => {
    console.log('\n=== Scan Results ===\n');
    
    // Display target information
    console.log(`Target: ${results.target.original}`);
    console.log(`Hostname: ${results.target.hostname}`);
    console.log(`Scan completed in: ${results.scanDurationMs / 1000} seconds`);
    
    // Display any errors
    if (results.errors && results.errors.length) {
      console.log('\n=== Errors ===');
      results.errors.forEach(err => {
        console.log(`- [${err.component}] ${err.message}`);
      });
    }
    
    // Display ports
    if (results.ports && results.ports.length) {
      console.log('\n=== Open Ports ===');
      results.ports.forEach(port => {
        console.log(`- ${port.port}/${port.protocol}: ${port.service} ${port.version}`);
      });
    } else {
      console.log('\nNo open ports detected');
    }
    
    // Display HTTP information if available
    if (results.http) {
      console.log('\n=== HTTP Information ===');
      console.log(`Status: ${results.http.statusCode} ${results.http.statusMessage}`);
      console.log(`Server: ${results.http.server}`);
      console.log(`Content-Type: ${results.http.contentType}`);
      
      console.log('\n=== Security Headers ===');
      const secHeaders = results.http.securityHeaders || {};
      console.log(`- Strict-Transport-Security: ${secHeaders.hasStrictTransportSecurity ? 'Yes' : 'No'}`);
      console.log(`- Content-Security-Policy: ${secHeaders.hasContentSecurityPolicy ? 'Yes' : 'No'}`);
      console.log(`- X-Content-Type-Options: ${secHeaders.hasXContentTypeOptions ? 'Yes' : 'No'}`);
      console.log(`- X-Frame-Options: ${secHeaders.hasXFrameOptions ? 'Yes' : 'No'}`);
      console.log(`- X-XSS-Protection: ${secHeaders.hasXXSSProtection ? 'Yes' : 'No'}`);
      console.log(`- Referrer-Policy: ${secHeaders.hasReferrerPolicy ? 'Yes' : 'No'}`);
      console.log(`- Permissions-Policy: ${secHeaders.hasPermissionsPolicy ? 'Yes' : 'No'}`);
    }
    
    // Save to file if specified
    if (outputFile) {
      fs.writeFileSync(path.resolve(outputFile), JSON.stringify(results, null, 2));
      console.log(`\nFull results saved to: ${outputFile}`);
    }
  })
  .catch((error) => {
    console.error('Scan failed:', error.message);
    process.exit(1);
  });
