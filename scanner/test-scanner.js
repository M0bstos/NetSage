/**
 * Test script for the NetSage scanner with multi-strategy scanning
 * This script will test different scan strategies against various targets
 */

const Scanner = require('./lib/scanner');
const fs = require('fs');
const path = require('path');

// Test targets of varying complexity
const targets = [
  'example.com',                 // Simple website
  'scanme.nmap.org',             // Nmap's test site
  'httpbin.org',                 // API testing site
  'portquiz.net'                 // Open port testing site
];

// Test different scan configurations
async function runTests() {
  console.log('🚀 Starting NetSage Scanner Tests with Multi-strategy Scanning');
  console.log('===========================================================');

  const results = [];
  
  for (const target of targets) {
    console.log(`\n📡 Testing target: ${target}`);
    
    // Test standard scan
    console.log('  🔍 Running standard scan...');
    const standardScanner = new Scanner({
      timeout: 30000,
      portScanTimeout: 90000,
      overallTimeout: 300000,
      enableUdpScan: false,  // First test without UDP
      adaptiveTimeouts: true
    });
    
    const standardResult = await standardScanner.scan(target);
    console.log(`  ✅ Standard scan completed with ${standardResult.ports.length} ports found`);
    results.push({
      target,
      scanType: 'standard',
      portsFound: standardResult.ports.length,
      errors: standardResult.errors.length,
      udpEnabled: false
    });
    
    // Test with UDP enabled
    console.log('  🔍 Running scan with UDP enabled...');
    const udpScanner = new Scanner({
      timeout: 30000,
      portScanTimeout: 90000,
      overallTimeout: 300000,
      enableUdpScan: true,
      adaptiveTimeouts: true
    });
    
    const udpResult = await udpScanner.scan(target);
    console.log(`  ✅ UDP-enabled scan completed with ${udpResult.ports.length} ports found`);
    results.push({
      target,
      scanType: 'udp-enabled',
      portsFound: udpResult.ports.length,
      errors: udpResult.errors.length,
      udpEnabled: true
    });
    
    // Save the full results for this target
    const resultDir = path.join(__dirname, 'scan-results');
    if (!fs.existsSync(resultDir)) {
      fs.mkdirSync(resultDir, { recursive: true });
    }
    
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    fs.writeFileSync(
      path.join(resultDir, `test-${target.replace(/\./g, '-')}-${timestamp}.json`),
      JSON.stringify(udpResult, null, 2)
    );
    
    console.log(`  💾 Saved full scan results for ${target}`);
  }
  
  // Print summary table
  console.log('\n📊 Scan Results Summary');
  console.log('=====================');
  console.log('Target\t\tScan Type\tUDP\tPorts\tErrors');
  console.log('------\t\t---------\t---\t-----\t------');
  
  for (const result of results) {
    console.log(`${result.target.padEnd(15)}\t${result.scanType.padEnd(10)}\t${result.udpEnabled ? 'Yes' : 'No'}\t${result.portsFound}\t${result.errors}`);
  }
}

runTests().catch(err => {
  console.error('Test failed with error:', err);
  process.exit(1);
});
