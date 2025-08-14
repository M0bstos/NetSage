/**
 * NetSage Website Scanner
 * 
 * Express server for webhook endpoints to receive scan requests and trigger scanning.
 * Performs port scanning, service detection, and vulnerability scanning using Nuclei.
 */

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const Scanner = require('./lib/scanner');

// Load environment variables
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || 'localhost';
const CALLBACK_URL = process.env.CALLBACK_URL || 'http://localhost:3000/api/webhooks/scan-result';

// Ensure scan results directory exists
const RESULTS_DIR = process.env.RESULTS_DIR || path.join(__dirname, 'scan-results');
if (!fs.existsSync(RESULTS_DIR)) {
  console.log(`Creating scan results directory: ${RESULTS_DIR}`);
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
}

// Initialize Express app
const app = express();

// Configure CORS with specific options
const corsOptions = {
  origin: '*', // Allow all origins
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};
app.use(cors(corsOptions)); // Enable CORS with options

app.use(bodyParser.json());

// Create a map to store active scans
const activeScans = new Map();

/**
 * Format scan results to match the expected format for the backend
 * 
 * @param {string} requestId - The UUID of the scan request
 * @param {object} scanResults - The raw scan results from the scanner
 * @returns {object} - Formatted results for the backend
 */
/**
 * Format scan results to match the expected format for the backend
 * Enhanced version includes comprehensive vulnerability data from Nuclei
 * 
 * @param {string} requestId - The UUID of the scan request
 * @param {object} scanResults - The raw scan results from the scanner
 * @returns {object} - Formatted results for the backend
 */
function formatResultsForBackend(requestId, scanResults) {
  // Initialize the formatted results with consistent structure
  const formattedResults = {
    request_id: requestId,
    scan_data: [],
    scan_timestamp: new Date().toISOString(),
    scan_duration_ms: scanResults.scanDurationMs || 0,
    // Always include scan_metadata section
    scan_metadata: {
      target_url: scanResults.target.original || "",
      hostname: scanResults.target.hostname || "",
      protocol: scanResults.target.protocol || "",
      scan_techniques: {
        port_scan: scanResults.ports !== undefined,
        http_analysis: scanResults.http !== undefined,
        vulnerability_scan: scanResults.nuclei && scanResults.nuclei.enabled !== false,
        alternative_detection: scanResults.alternative_detection !== undefined
      },
      // Add scan status information if available
      scan_status: scanResults.scan_status || {
        port_scan: { success: true, results_found: scanResults.ports && scanResults.ports.length > 0 },
        http_analysis: { success: scanResults.http !== null },
        vulnerability_scan: { 
          success: scanResults.nuclei && scanResults.nuclei.findings !== undefined,
          results_found: scanResults.nuclei && scanResults.nuclei.findings && scanResults.nuclei.findings.length > 0
        },
        alternative_detection: scanResults.alternative_detection ? {
          success: scanResults.alternative_detection.success,
          results_found: scanResults.alternative_detection.technologies_detected && 
                         scanResults.alternative_detection.technologies_detected.length > 0,
          methods_applied: scanResults.alternative_detection.methods_applied || []
        } : undefined
      }
    },
    // Include errors section
    errors: scanResults.errors || [],
    // Always include http_security section (even if empty)
    http_security: {
      target: scanResults.target.hostname || "",
      headers: {
        hasStrictTransportSecurity: false,
        hasContentSecurityPolicy: false,
        hasXContentTypeOptions: false,
        hasXFrameOptions: false,
        hasXXSSProtection: false,
        hasReferrerPolicy: false,
        hasPermissionsPolicy: false,
        strictTransportSecurityValue: null,
        contentSecurityPolicyValue: null,
        xContentTypeOptionsValue: null,
        xFrameOptionsValue: null,
        xxssProtectionValue: null,
        referrerPolicyValue: null,
        permissionsPolicyValue: null
      }
    },
    // Always include vulnerabilities section
    vulnerabilities: [],
    // Always include vulnerability summary
    vulnerability_summary: {
      total_count: 0,
      by_severity: {}
    }
  };

  // Extract target hostname
  const target = scanResults.target.hostname;

  // Add port information from nmap scan
  if (scanResults.ports && scanResults.ports.length > 0) {
    console.log(`Found ${scanResults.ports.length} open ports to report`);
    scanResults.ports.forEach(port => {
      formattedResults.scan_data.push({
        target: target,
        port: parseInt(port.port),
        protocol: port.protocol || 'tcp',
        service: port.service || 'unknown',
        product: port.service || 'unknown',  // Always include product field
        version: port.version || '',
        state: port.state || 'open',
        banner: port.banner || ''
      });
    });
  }

  // Add HTTP service information regardless of port scan results
  if (scanResults.http) {
    // Extract port from HTTP URL or use default based on protocol
    let port = scanResults.target.port;
    if (!port) {
      port = scanResults.target.protocol === 'https' ? 443 : 80;
    }
    const service = scanResults.target.protocol === 'https' ? 'https' : 'http';
    
    // Only add if not already added from port scan
    if (!formattedResults.scan_data.some(item => 
      (item.port === parseInt(port) && (item.service === 'http' || item.service === 'https')))) {
      console.log(`Adding HTTP service information on port ${port}`);
      formattedResults.scan_data.push({
        target: target,
        port: parseInt(port) || null, // Handle case when port cannot be parsed
        service: service,
        product: scanResults.http.server !== 'unknown' ? scanResults.http.server : service,
        version: '',
        state: 'open',
        banner: ''
      });
    }

    // Always update the http_security section with actual data if available
    if (scanResults.http.securityHeaders) {
      formattedResults.http_security = {
        target: target,
        headers: scanResults.http.securityHeaders
      };
    }
  }

  // If no service found, still include at least one entry with protocol information
  if (formattedResults.scan_data.length === 0) {
    const defaultProtocol = scanResults.target.protocol || 'http';
    const defaultPort = defaultProtocol === 'https' ? 443 : 80;
    
    console.log(`No services detected, adding default ${defaultProtocol} service information`);
    formattedResults.scan_data.push({
      target: target,
      port: null, // When port detection fails completely
      service: defaultProtocol,
      product: defaultProtocol,
      version: '',
      state: 'unknown',
      banner: ''
    });
  }
  
  // ENHANCED: Add Nuclei findings if available, with extra checks
  // First check explicitly if nuclei findings are available
  // Check both places where Nuclei findings might be stored
  let nucleiFindings = [];
  
  // Check if findings are in nuclei.findings (regular path)
  if (scanResults.nuclei && Array.isArray(scanResults.nuclei.findings) && scanResults.nuclei.findings.length > 0) {
    nucleiFindings = scanResults.nuclei.findings;
    console.log('Found Nuclei findings in scanResults.nuclei.findings');
  } 
  // Check if findings are directly in the vulnerabilities property (already processed)
  else if (scanResults.vulnerabilities && Array.isArray(scanResults.vulnerabilities) && scanResults.vulnerabilities.length > 0) {
    nucleiFindings = scanResults.vulnerabilities;
    console.log('Found Nuclei findings in scanResults.vulnerabilities');
  }
  
  if (nucleiFindings.length > 0) {
    console.log(`Found ${nucleiFindings.length} vulnerabilities/findings to report`);
    
    // Group findings by severity
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
    const bySeverity = {};
    
    nucleiFindings.forEach(finding => {
      const sev = finding.severity || 'unknown';
      if (!bySeverity[sev]) bySeverity[sev] = [];
      bySeverity[sev].push(finding);
    });
    
    // Log severity breakdown
    severityOrder.forEach(sev => {
      if (bySeverity[sev]) {
        console.log(`  ${sev.toUpperCase()}: ${bySeverity[sev].length} findings`);
      }
    });
    
    // Format findings for the backend
    formattedResults.vulnerabilities = nucleiFindings.map(finding => {
      return {
        target: target,
        name: finding.name || 'Unknown',
        severity: finding.severity || 'unknown',
        type: finding.type || 'unknown',
        description: finding.description || '',
        matched: finding.matched || finding.url || finding.host || '',
        cves: finding.cve || [],
        references: finding.reference || [],
        tags: finding.tags || [],
        timestamp: finding.timestamp || new Date().toISOString()
      };
    });
    
    // Update vulnerability summary
    formattedResults.vulnerability_summary = {
      total_count: nucleiFindings.length,
      by_severity: {}
    };
    
    severityOrder.forEach(sev => {
      if (bySeverity[sev]) {
        formattedResults.vulnerability_summary.by_severity[sev] = bySeverity[sev].length;
      } else {
        // Include all severity levels with 0 count for consistency
        formattedResults.vulnerability_summary.by_severity[sev] = 0;
      }
    });
    
    // Add a marker to indicate we have processed the findings
    formattedResults.nuclei_findings_processed = true;
  } else {
    console.log('No vulnerability findings to report');
    // Initialize summary with zero counts for all severity levels
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
    severityOrder.forEach(sev => {
      formattedResults.vulnerability_summary.by_severity[sev] = 0;
    });
  }
  
  // Add alternative detection information if available
  if (scanResults.alternative_detection && scanResults.alternative_detection.performed) {
    console.log('Adding alternative detection results');
    formattedResults.alternative_detection = {
      success: scanResults.alternative_detection.success,
      methods_applied: scanResults.alternative_detection.methods_applied || [],
      technologies_detected: scanResults.alternative_detection.technologies_detected || []
    };
    
    // Add detected technologies if any
    if (scanResults.alternative_detection.technologies_detected && 
        scanResults.alternative_detection.technologies_detected.length > 0) {
      
      // Create a technologies section if it doesn't already exist
      if (!formattedResults.technologies) {
        formattedResults.technologies = [];
      }
      
      // Add each technology detected through alternative methods
      scanResults.alternative_detection.technologies_detected.forEach(tech => {
        // Only add if not already present
        const techName = tech.name.toLowerCase();
        if (!formattedResults.technologies.some(t => t.name.toLowerCase() === techName)) {
          formattedResults.technologies.push({
            name: tech.name,
            version: tech.version || '',
            category: tech.category || tech.type || 'unknown',
            detection_method: 'alternative',
            confidence: tech.confidence || 'medium'
          });
        }
      });
    }
    
    // Add SSL/TLS information if available
    if (scanResults.alternative_detection.tls_info) {
      formattedResults.ssl_info = scanResults.alternative_detection.tls_info;
    }
    
    // Add security products if detected
    if (scanResults.alternative_detection.security_products && 
        scanResults.alternative_detection.security_products.length > 0) {
      
      formattedResults.security_products = scanResults.alternative_detection.security_products;
    }
  }

  return formattedResults;
}

/**
 * Send scan results back to the main backend with retries
 * 
 * @param {string} requestId - The UUID of the scan request
 * @param {object} results - The formatted scan results
 * @param {number} retryCount - Number of retries attempted (internal use)
 * @returns {Promise<boolean>} - Success status of the operation
 */
// Simple check to ensure we have the latest Nuclei findings
async function ensureNucleiResultsMerged(results) {
  // Check if we already have vulnerabilities
  if (results.vulnerabilities && results.vulnerabilities.length > 0) {
    console.log(`Results already contain ${results.vulnerabilities.length} vulnerabilities - no need to check Nuclei files`);
    return results;
  }
  
  console.log('Final safety check for Nuclei findings before sending to backend...');
  
  try {
    // Look for the most recent Nuclei file
    const resultsDir = RESULTS_DIR;
    const files = fs.readdirSync(resultsDir)
      .filter(file => file.startsWith('nuclei-'))
      .map(file => ({
        name: file,
        path: path.join(resultsDir, file),
        time: fs.statSync(path.join(resultsDir, file)).mtime.getTime()
      }))
      .sort((a, b) => b.time - a.time);
    
    if (files.length > 0) {
      const latestFile = files[0];
      const fileAge = Date.now() - latestFile.time;
      
      // Only use the file if it's recent (created in the last 5 minutes)
      if (fileAge < 300000) { 
        const content = fs.readFileSync(latestFile.path, 'utf8');
        if (content && content.trim() !== '[]') {
          const findings = JSON.parse(content);
          if (Array.isArray(findings) && findings.length > 0) {
            console.log(`Safety check found ${findings.length} Nuclei findings in ${latestFile.name}`);
            
            // Get target from results
            const target = results.scan_data && results.scan_data.length > 0 
              ? results.scan_data[0].target 
              : 'unknown';
            
            // Format the findings for backend
            results.vulnerabilities = findings.map(finding => ({
              target: target,
              name: finding.name || 'Unknown',
              severity: finding.severity || 'unknown',
              type: finding.type || 'unknown',
              description: finding.description || '',
              matched: finding.matched || finding.url || finding.host || '',
              cves: finding.cve || [],
              references: finding.reference || [],
              tags: finding.tags || [],
              timestamp: finding.timestamp || new Date().toISOString()
            }));
            
            // Update vulnerability summary
            const severityOrder = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
            const bySeverity = {};
            findings.forEach(finding => {
              const sev = finding.severity || 'unknown';
              if (!bySeverity[sev]) bySeverity[sev] = 0;
              bySeverity[sev]++;
            });
            
            results.vulnerability_summary = {
              total_count: findings.length,
              by_severity: {}
            };
            
            severityOrder.forEach(sev => {
              results.vulnerability_summary.by_severity[sev] = bySeverity[sev] || 0;
            });
            
            console.log('Successfully merged Nuclei findings in safety check');
          }
        }
      }
    }
  } catch (error) {
    console.warn(`Error in Nuclei safety check: ${error.message}`);
  }
  
  return results;
}

async function sendResultsToBackend(requestId, results, retryCount = 0) {
  const MAX_RETRIES = 3;
  const RETRY_DELAY = 5000; // 5 seconds
  
  // Simple safety check to ensure Nuclei results are merged before sending
  results = await ensureNucleiResultsMerged(results);
  
  try {
    console.log(`Sending results for request ${requestId} to ${CALLBACK_URL}`);
    console.log(`Payload size: ${JSON.stringify(results).length} bytes`);
    
    // Log whether vulnerabilities were found
    if (results.vulnerabilities && results.vulnerabilities.length > 0) {
      console.log(`Sending payload with ${results.vulnerabilities.length} vulnerabilities`);
    } else {
      console.log('No vulnerabilities included in the payload');
    }
    
    // Save a copy of the payload for debugging
    try {
      const debugPath = path.join(RESULTS_DIR, `backend-payload-${requestId}.json`);
      fs.writeFileSync(debugPath, JSON.stringify(results, null, 2));
    } catch (err) {
      console.warn(`Could not save debug payload: ${err.message}`);
    }
    
    // Send data to backend with timeout
    const response = await axios.post(CALLBACK_URL, results, {
      headers: { 
        'Content-Type': 'application/json',
        'X-Request-ID': requestId,
        'X-Scanner-Version': '1.1.0'
      },
      timeout: 30000 // 30 second timeout
    });
    
    if (response.status >= 200 && response.status < 300) {
      console.log(`Successfully sent results for request ${requestId}`);
      console.log(`Response from backend: ${response.status} ${response.statusText}`);
      return true;
    } else {
      console.error(`Failed to send results: ${response.status} ${response.statusText}`);
      
      // Retry logic for non-successful responses
      if (retryCount < MAX_RETRIES) {
        console.log(`Retrying (${retryCount + 1}/${MAX_RETRIES}) in ${RETRY_DELAY/1000} seconds...`);
        await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
        return sendResultsToBackend(requestId, results, retryCount + 1);
      }
      
      return false;
    }
  } catch (error) {
    console.error(`Error sending results to backend: ${error.message}`);
    
    // Retry logic for exceptions
    if (retryCount < MAX_RETRIES) {
      console.log(`Retrying (${retryCount + 1}/${MAX_RETRIES}) in ${RETRY_DELAY/1000} seconds...`);
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
      return sendResultsToBackend(requestId, results, retryCount + 1);
    }
    
    return false;
  }
}

/**
 * Run a scan for the given target and request ID
 * 
 * @param {string} target - URL or hostname to scan
 * @param {string} requestId - The UUID of the scan request
 */
/**
 * Run a comprehensive scan for the given target and request ID
 * Includes port scanning, service detection, and vulnerability scanning
 * 
 * @param {string} target - URL or hostname to scan
 * @param {string} requestId - The UUID of the scan request
 */
async function runScan(target, requestId) {
  try {
    console.log(`Starting comprehensive scan for ${target} with request ID ${requestId}`);
    
    // Generate a timestamp-based filename for scan results
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    const resultsFilename = `scan-${requestId}-${timestamp}.json`;
    const resultsPath = path.join(RESULTS_DIR, resultsFilename);
    
    // Determine if we should run a comprehensive scan
    const isComprehensive = process.env.COMPREHENSIVE_SCAN === 'true';
    
    // Default templates based on scan type
    let templates = ['technologies']; // Default safer option
    
    if (isComprehensive) {
      templates = ['cves', 'vulnerabilities', 'exposures', 'misconfigurations', 'technologies', 'default-logins'];
      console.log(`Running comprehensive scan with templates: ${templates.join(', ')}`);
    } else {
      // Get templates from env or use default
      templates = (process.env.NUCLEI_TEMPLATES || 'technologies,cves').split(',');
      console.log(`Running standard scan with templates: ${templates.join(', ')}`);
    }
    
    // Enhanced timeout configuration with environment variables
    // These timeouts are separate for each component of the scan
    
    // Base timeouts - configured through environment variables
    const basePortScanTimeout = parseInt(process.env.PORT_SCAN_TIMEOUT || '120000');  // 2 minutes default
    const baseHttpTimeout = parseInt(process.env.HTTP_SCAN_TIMEOUT || '60000');       // 1 minute default
    const baseNucleiTimeout = parseInt(process.env.NUCLEI_SCAN_TIMEOUT || '300000');  // 5 minutes default
    
    // Comprehensive scan multipliers
    const comprehensiveMultiplier = isComprehensive ? 2 : 1; // Double timeouts for comprehensive scans
    
    // Calculate final timeouts
    const portScanTimeout = basePortScanTimeout * comprehensiveMultiplier;
    const httpTimeout = baseHttpTimeout * comprehensiveMultiplier;
    const nucleiTimeout = baseNucleiTimeout * comprehensiveMultiplier;
    
    // Overall scan timeout (the maximum time the entire scan should take)
    const overallScanTimeout = parseInt(process.env.OVERALL_SCAN_TIMEOUT || '600000') * comprehensiveMultiplier; // 10 minutes (20 for comprehensive)
    
    console.log(`Configured timeouts - Port scan: ${portScanTimeout/1000}s, HTTP: ${httpTimeout/1000}s, Nuclei: ${nucleiTimeout/1000}s, Overall: ${overallScanTimeout/1000}s`);
    
    // Phase 4, Step 1: Configure evasion options
    const enableEvasion = process.env.ENABLE_EVASION !== 'false'; // Enable evasion by default
    const evasionProfile = process.env.EVASION_PROFILE || 'moderate'; // Default to moderate
    
    // Configure individual evasion techniques
    const evasionOptions = {
      enableFragmentation: process.env.ENABLE_FRAGMENTATION !== 'false', // IP fragmentation
      enableDecoys: process.env.ENABLE_DECOYS !== 'false', // Decoy scan
      enableSourcePort: process.env.ENABLE_SOURCE_PORT !== 'false', // Source port manipulation
      enableRandomization: process.env.ENABLE_RANDOMIZATION !== 'false' // Randomized scan order
    };
    
    if (enableEvasion) {
      console.log(`Evasion techniques enabled with profile: ${evasionProfile}`);
    }
    
    // Create scanner with enhanced timeout, evasion settings, and alternative detection
    const scanner = new Scanner({
      timeout: httpTimeout, // General HTTP timeout
      portScanTimeout: portScanTimeout, // Specific timeout for port scanning
      overallTimeout: overallScanTimeout, // Maximum time for the entire scan
      ports: process.env.DEFAULT_PORTS_TO_SCAN || '21,22,25,80,443,3306,8080,8443',
      aggressive: process.env.AGGRESSIVE_SCAN === 'true',
      enableNuclei: process.env.ENABLE_NUCLEI !== 'false', // Enable by default
      adaptiveTimeouts: process.env.ADAPTIVE_TIMEOUTS !== 'false', // Enable adaptive timeouts by default
      // Phase 4, Step 1: Add evasion options
      enableEvasion: enableEvasion,
      evasionProfile: evasionProfile,
      evasionOptions: evasionOptions,
      // Phase 4, Step 2: Add alternative detection options
      enableAlternativeDetection: process.env.ENABLE_ALTERNATIVE_DETECTION === 'true',
      alternativeDetectionOptions: {
        enableSSL: process.env.ALTERNATIVE_DETECTION_SSL !== 'false',
        enableHTTP: process.env.ALTERNATIVE_DETECTION_HTTP !== 'false',
        enableJS: process.env.ALTERNATIVE_DETECTION_JS !== 'false',
        timeout: parseInt(process.env.ALTERNATIVE_DETECTION_TIMEOUT || '15000')
      },
      // Phase 4, Step 3: Add proxy support options
      enableProxySupport: process.env.ENABLE_PROXY_SUPPORT === 'true',
      proxyOptions: {
        proxyList: (() => {
          try {
            return JSON.parse(process.env.PROXY_LIST || '[]');
          } catch (error) {
            console.warn('Failed to parse PROXY_LIST environment variable, using empty array');
            return [];
          }
        })(),
        enableTor: process.env.ENABLE_TOR === 'true',
        rotateUserAgents: process.env.ROTATE_USER_AGENTS !== 'false',
        enableConnectionPooling: process.env.ENABLE_CONNECTION_POOLING !== 'false',
        maxPoolSize: parseInt(process.env.MAX_POOL_SIZE || '10'),
        poolTimeout: parseInt(process.env.POOL_TIMEOUT || '30000'),
        torProxy: {
          protocol: process.env.TOR_PROXY_PROTOCOL || 'socks5',
          host: process.env.TOR_PROXY_HOST || '127.0.0.1',
          port: parseInt(process.env.TOR_PROXY_PORT || '9050')
        }
      },
      nucleiOptions: {
        templates: templates,
        nucleiPath: process.env.NUCLEI_PATH || 'nuclei',
        outputDir: RESULTS_DIR,
        timeout: nucleiTimeout, // Use the Nuclei-specific timeout
        rateLimit: process.env.NUCLEI_RATE_LIMIT || '150', // Rate limiting to avoid blocks
        concurrency: process.env.NUCLEI_CONCURRENCY || '25' // Concurrent template execution
      }
    });
    
    // Track the scan
    activeScans.set(requestId, {
      target,
      startTime: Date.now(),
      status: 'scanning',
      type: isComprehensive ? 'comprehensive' : 'standard',
      resultsPath
    });
    
    console.log(`Starting scan execution...`);
    
    // Run the scan
    const startTime = Date.now();
    const results = await scanner.scan(target);
    const duration = Date.now() - startTime;
    
    // Add duration to results
    results.scanDurationMs = duration;
    
    console.log(`Scan completed in ${(duration / 1000).toFixed(2)} seconds`);
    
    // SIMPLE FIX: Wait for Nuclei scan to complete and get its results
    console.log('Waiting for Nuclei scan to complete (15 seconds)...');
    
    // Initialize nuclei findings array
    let nucleiFindings = [];
    
    // Wait for Nuclei to complete (simple fixed wait period)
    // This gives enough time for the Nuclei scan to finish and write results
    await new Promise(resolve => {
      const waitTime = 15000; // 15 seconds wait
      const checkInterval = 1000; // Check every second
      let elapsed = 0;
      
      // Check periodically for new Nuclei files
      const intervalId = setInterval(() => {
        elapsed += checkInterval;
        console.log(`Waiting for Nuclei scan: ${elapsed/1000}s of ${waitTime/1000}s elapsed...`);
        
        // Try to find any new Nuclei results
        try {
          const resultsDir = path.join(__dirname, 'scan-results');
          const files = fs.readdirSync(resultsDir)
            .filter(file => file.startsWith('nuclei-'))
            .map(file => ({
              name: file,
              path: path.join(resultsDir, file),
              time: fs.statSync(path.join(resultsDir, file)).mtime.getTime()
            }))
            .sort((a, b) => b.time - a.time); // Sort by most recent
          
          if (files.length > 0) {
            const recentFile = files[0];
            const fileAge = Date.now() - recentFile.time;
            console.log(`Most recent Nuclei file: ${recentFile.name} (${fileAge/1000}s old)`);
            
            // If we found a very recent file (created in the last minute)
            if (fileAge < 60000) {
              try {
                const content = fs.readFileSync(recentFile.path, 'utf8');
                if (content && content.trim() !== '[]') {
                  const findings = JSON.parse(content);
                  if (Array.isArray(findings) && findings.length > 0) {
                    console.log(`Found ${findings.length} Nuclei findings in ${recentFile.name}`);
                    nucleiFindings = findings;
                    
                    // We found results, can resolve early
                    clearInterval(intervalId);
                    resolve();
                    return;
                  }
                }
              } catch (error) {
                console.warn(`Error checking Nuclei file ${recentFile.name}: ${error.message}`);
              }
            }
          }
        } catch (error) {
          console.warn(`Error checking for Nuclei files: ${error.message}`);
        }
        
        // If time is up, resolve the promise
        if (elapsed >= waitTime) {
          clearInterval(intervalId);
          resolve();
        }
      }, checkInterval);
    });
        
    // After the wait period, check if we found any Nuclei findings
    if (nucleiFindings.length > 0) {
      console.log(`Successfully found ${nucleiFindings.length} Nuclei findings after waiting`);
    } else {
      console.log('No Nuclei findings found after waiting period');
      
      // Try one last check of the latest Nuclei file
      try {
        const resultsDir = path.join(__dirname, 'scan-results');
        const newestFiles = fs.readdirSync(resultsDir)
          .filter(file => file.startsWith('nuclei-'))
          .map(file => ({
            name: file,
            path: path.join(resultsDir, file),
            time: fs.statSync(path.join(resultsDir, file)).mtime.getTime()
          }))
          .sort((a, b) => b.time - a.time);
          
        if (newestFiles.length > 0) {
          const latestFile = newestFiles[0];
          try {
            const content = fs.readFileSync(latestFile.path, 'utf8');
            if (content && content.trim() !== '[]') {
              const findings = JSON.parse(content);
              if (Array.isArray(findings) && findings.length > 0) {
                console.log(`Last chance: Found ${findings.length} Nuclei findings in ${latestFile.name}`);
                nucleiFindings = findings;
              }
            }
          } catch (error) {
            console.warn(`Error reading the latest Nuclei file: ${error.message}`);
          }
        }
      } catch (error) {
        console.error(`Error in final Nuclei check: ${error.message}`);
      }
    }
    
    // Merge any found Nuclei findings into the results
    if (nucleiFindings.length > 0) {
      if (!results.nuclei) {
        results.nuclei = {};
      }
      results.nuclei.findings = nucleiFindings;
      
      // Update scan status
      if (!results.scan_status.vulnerability_scan) {
        results.scan_status.vulnerability_scan = {};
      }
      results.scan_status.vulnerability_scan.success = true;
      results.scan_status.vulnerability_scan.results_found = true;
      
      console.log(`Successfully merged ${nucleiFindings.length} Nuclei findings into scan results`);
    } else {
      console.log('No Nuclei findings found to merge with scan results');
    }
    
    // Format results for the backend
    const formattedResults = formatResultsForBackend(requestId, results);
    
    // Save results locally for reference
    try {
      fs.writeFileSync(resultsPath, JSON.stringify(formattedResults, null, 2), 'utf8');
      console.log(`Scan results saved to ${resultsPath}`);
    } catch (saveError) {
      console.error(`Error saving results to file: ${saveError.message}`);
    }
    
    // Update scan status
    activeScans.set(requestId, {
      ...activeScans.get(requestId),
      status: 'sending',
      completionTime: Date.now(),
      duration,
      findings: results.nuclei?.findings?.length || 0
    });
    
    console.log(`Sending results to backend...`);
    
    // Send results to backend
    await sendResultsToBackend(requestId, formattedResults);
    
    // Mark as completed
    activeScans.set(requestId, {
      ...activeScans.get(requestId),
      status: 'completed'
    });
    
    console.log(`Scan completed for ${target} with request ID ${requestId}`);
    if (formattedResults.vulnerabilities && formattedResults.vulnerabilities.length > 0) {
      console.log(`Found ${formattedResults.vulnerabilities.length} potential vulnerabilities`);
    }
    
    return formattedResults;
    
  } catch (error) {
    console.error(`Error scanning ${target}: ${error.message}`);
    
    // Mark as failed
    activeScans.set(requestId, {
      ...activeScans.get(requestId),
      status: 'failed',
      error: error.message
    });
    
    // Send error to backend
    const errorResult = {
      request_id: requestId,
      scan_data: [],
      error: error.message,
      timestamp: new Date().toISOString()
    };
    
    await sendResultsToBackend(requestId, errorResult);
    return errorResult;
  }
}

// Routes

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'up',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * Test endpoint to check CORS and connectivity
 */
app.get('/test', (req, res) => {
  console.log('Received test request with headers:', req.headers);
  res.json({
    success: true,
    message: 'Test endpoint working correctly',
    cors: 'enabled',
    timestamp: new Date().toISOString()
  });
});

/**
 * Scan request endpoint - receives requests from the main backend
 */
app.post('/scan', async (req, res) => {
  try {
    console.log('Received scan request with headers:', req.headers);
    console.log('Request body:', req.body);
    
    const { website_url, requestId, options = {} } = req.body;
    
    if (!website_url) {
      console.log('Missing required parameter: website_url');
      return res.status(400).json({
        success: false,
        message: 'Missing required parameter: website_url'
      });
    }
    
    // Validate URL format
    try {
      new URL(website_url.startsWith('http') ? website_url : `http://${website_url}`);
    } catch (urlError) {
      console.log(`Invalid URL format: ${website_url}`);
      return res.status(400).json({
        success: false,
        message: `Invalid URL format: ${website_url}`,
        error: urlError.message
      });
    }
    
    // Use provided requestId or generate a new one
    const scanRequestId = requestId || uuidv4();
    
    // Check if there's already a scan in progress for this URL
    const existingScan = Array.from(activeScans.values()).find(
      scan => scan.target === website_url && 
      ['scanning', 'sending'].includes(scan.status) && 
      (Date.now() - scan.startTime < 600000) // Less than 10 minutes old
    );
    
    if (existingScan) {
      console.log(`Already scanning ${website_url}, returning existing requestId ${existingScan.requestId}`);
      return res.json({
        success: true,
        message: 'Scan already in progress',
        requestId: existingScan.requestId,
        status: existingScan.status,
        startTime: new Date(existingScan.startTime).toISOString()
      });
    }
    
    console.log(`Processing scan for ${website_url} with requestId ${scanRequestId}`);
    
    // Set scan options from request (if provided)
    if (options.comprehensive === true) {
      process.env.COMPREHENSIVE_SCAN = 'true';
      console.log('Enabling comprehensive scan based on request options');
    }
    
    if (options.aggressive === true) {
      process.env.AGGRESSIVE_SCAN = 'true';
      console.log('Enabling aggressive scan based on request options');
    }
    
    // Respond immediately to the client
    res.json({
      success: true,
      message: 'Scan request received and processing',
      requestId: scanRequestId,
      estimatedTime: options.comprehensive ? '5-10 minutes' : '1-3 minutes'
    });
    
    // Run scan asynchronously
    runScan(website_url, scanRequestId)
      .then(results => {
        console.log(`Scan completed for requestId ${scanRequestId}`);
      })
      .catch(err => {
        console.error(`Scan failed for requestId ${scanRequestId}: ${err.message}`);
      })
      .finally(() => {
        // Reset environment variables after scan
        process.env.COMPREHENSIVE_SCAN = 'false';
        process.env.AGGRESSIVE_SCAN = 'false';
      });
    
  } catch (error) {
    console.error(`Error processing scan request: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

/**
 * Get scan status endpoint
 * Returns detailed information about a scan in progress or completed scan
 */
app.get('/status/:requestId', (req, res) => {
  const { requestId } = req.params;
  
  if (activeScans.has(requestId)) {
    const scan = activeScans.get(requestId);
    
    // Calculate elapsed time or duration
    let elapsedOrDuration;
    if (scan.completionTime) {
      elapsedOrDuration = scan.completionTime - scan.startTime; // Duration in ms
    } else {
      elapsedOrDuration = Date.now() - scan.startTime; // Elapsed ms
    }
    
    // Format timestamps for client
    const formattedStartTime = new Date(scan.startTime).toISOString();
    const formattedCompletionTime = scan.completionTime ? new Date(scan.completionTime).toISOString() : null;
    
    // Estimate remaining time based on typical scan duration
    let estimatedTimeRemaining = null;
    if (scan.status === 'scanning') {
      const typicalDuration = scan.type === 'comprehensive' ? 600000 : 300000; // 10 min or 5 min
      const remainingMs = Math.max(0, typicalDuration - elapsedOrDuration);
      estimatedTimeRemaining = Math.ceil(remainingMs / 60000) + ' minutes';
    }
    
    res.json({
      success: true,
      requestId,
      status: scan.status,
      target: scan.target,
      scanType: scan.type || 'standard',
      startTime: formattedStartTime,
      completionTime: formattedCompletionTime,
      elapsedTimeSeconds: Math.floor(elapsedOrDuration / 1000),
      estimatedTimeRemaining,
      findings: scan.findings || 0,
      error: scan.error || null,
      resultsAvailable: scan.status === 'completed'
    });
  } else {
    // Check if we have results saved on disk for this requestId
    const resultsDir = path.join(__dirname, 'scan-results');
    if (fs.existsSync(resultsDir)) {
      const files = fs.readdirSync(resultsDir);
      const resultFile = files.find(file => file.includes(requestId));
      
      if (resultFile) {
        const filePath = path.join(resultsDir, resultFile);
        try {
          res.json({
            success: true,
            requestId,
            status: 'archived',
            resultsAvailable: true,
            resultFile: resultFile,
            message: 'Scan completed but no longer active in memory. Results available on disk.'
          });
          return;
        } catch (err) {
          console.error(`Error reading archived result: ${err.message}`);
        }
      }
    }
    
    res.status(404).json({
      success: false,
      message: 'Scan not found',
      requestId
    });
  }
});

/**
 * Get scan results directly endpoint
 */
app.get('/results/:requestId', (req, res) => {
  const { requestId } = req.params;
  
  // First check if scan is active and completed
  if (activeScans.has(requestId) && activeScans.get(requestId).status === 'completed') {
    const scan = activeScans.get(requestId);
    
    // If we have the results path, read from the file
    if (scan.resultsPath && fs.existsSync(scan.resultsPath)) {
      try {
        const results = JSON.parse(fs.readFileSync(scan.resultsPath, 'utf8'));
        return res.json({
          success: true,
          requestId,
          results
        });
      } catch (err) {
        console.error(`Error reading results file: ${err.message}`);
        return res.status(500).json({
          success: false,
          message: 'Error reading scan results',
          error: err.message
        });
      }
    }
  }
  
  // Check if we have results saved on disk for this requestId
  const files = fs.existsSync(RESULTS_DIR) ? 
    fs.readdirSync(RESULTS_DIR).filter(file => file.includes(requestId)) : 
    [];
  
  if (files.length > 0) {
    // Find the most recent file that matches the requestId
    const resultFile = files.sort().reverse()[0];
    const filePath = path.join(RESULTS_DIR, resultFile);
    
    try {
      const results = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      return res.json({
        success: true,
        requestId,
        status: 'archived',
        results
      });
    } catch (err) {
      console.error(`Error reading archived result: ${err.message}`);
      return res.status(500).json({
        success: false,
        message: 'Error reading archived scan results',
        error: err.message
      });
    }
  }
  
  // No results found
  res.status(404).json({
    success: false,
    message: 'Scan results not found',
    requestId
  });
});

/**
 * List all active scans endpoint
 */
app.get('/scans', (req, res) => {
  const scans = Array.from(activeScans.entries()).map(([id, scan]) => ({
    requestId: id,
    target: scan.target,
    status: scan.status,
    startTime: new Date(scan.startTime).toISOString(),
    completionTime: scan.completionTime ? new Date(scan.completionTime).toISOString() : null,
    findings: scan.findings || 0,
    type: scan.type || 'standard'
  }));
  
  // Sort by start time (newest first)
  scans.sort((a, b) => new Date(b.startTime) - new Date(a.startTime));
  
  res.json({
    success: true,
    count: scans.length,
    scans
  });
});

// Start the server
app.listen(PORT, HOST, () => {
  console.log(`NetSage Scanner server listening at http://${HOST}:${PORT}`);
  console.log(`Callback URL for results: ${CALLBACK_URL}`);
});
