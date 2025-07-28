/**
 * Scanner Core Module
 * 
 * This module implements the core scanning functionality for the NetSage website scanner.
 * It performs port scanning, service detection, version detection, and HTTP header analysis.
 * It also integrates with Nuclei for vulnerability scanning.
 */

const nmap = require('node-nmap');
const axios = require('axios');
const { URL } = require('url');
const NucleiScanner = require('./nuclei');

// Configure nmap path if necessary
// nmap.nmapLocation = 'path/to/nmap'; // Uncomment and set if nmap is not in PATH

class Scanner {
  /**
   * Creates a new scanner instance with enhanced timeout handling
   * @param {Object} options - Scanner options
   * @param {number} options.timeout - General timeout in milliseconds for scan operations
   * @param {number} options.portScanTimeout - Specific timeout for port scanning operations
   * @param {number} options.overallTimeout - Maximum time for the entire scan process
   * @param {string} options.ports - Comma-separated list of ports to scan
   * @param {boolean} options.aggressive - Whether to use aggressive scanning techniques
   * @param {boolean} options.enableNuclei - Whether to enable Nuclei vulnerability scanning
   * @param {boolean} options.adaptiveTimeouts - Whether to use adaptive timeouts based on target response
   * @param {Object} options.nucleiOptions - Options for Nuclei scanning
   */
  constructor(options = {}) {
    // Enhanced timeout configuration
    this.timeout = options.timeout || 30000; // Default 30 seconds (general timeout)
    this.portScanTimeout = options.portScanTimeout || 120000; // Default 2 minutes for port scans
    this.overallTimeout = options.overallTimeout || 600000; // Default 10 minutes overall timeout
    this.adaptiveTimeouts = options.adaptiveTimeouts !== false; // Enable adaptive timeouts by default
    
    // Store the start time for adaptive timeout calculations
    this.scanStartTime = null;
    this.timeoutMultipliers = {
      responsive: 0.75, // Reduce timeout for responsive targets
      normal: 1.0,      // Standard timeout
      slow: 1.5         // Increase timeout for slow targets
    };
    this.targetResponseCategory = 'normal'; // Default assumption
    
    // Other scanner settings
    this.ports = options.ports || '21,22,25,80,443,3306,8080,8443';
    this.aggressive = options.aggressive || false;
    this.enableNuclei = options.enableNuclei || false;
    this.enableUdpScan = options.enableUdpScan !== false; // Enable UDP scanning by default
    this.udpPorts = options.udpPorts || '53,67,68,69,123,137,138,139,161,162,445,500,514,520,631,1434,1900,5353';
    
    // Initialize Nuclei scanner if enabled
    if (this.enableNuclei) {
      this.nucleiScanner = new NucleiScanner({
        // Use specific Nuclei timeout or calculate based on overall timeout
        timeout: (options.nucleiOptions && options.nucleiOptions.timeout) || 
                Math.min(options.overallTimeout * 0.7 || 300000, 300000), // Max 5 minutes or 70% of overall
        ...options.nucleiOptions
      });
    }
    
    console.log(`Scanner initialized with timeouts - General: ${this.timeout}ms, Port scan: ${this.portScanTimeout}ms, Overall: ${this.overallTimeout}ms, Adaptive: ${this.adaptiveTimeouts}`);
  }
  
  /**
   * Calculate adaptive timeout based on target response times
   * @param {string} operation - The operation to calculate timeout for ('port', 'http', 'nuclei')
   * @param {number} baseTimeout - The base timeout value
   * @returns {number} The adjusted timeout value
   */
  calculateAdaptiveTimeout(operation, baseTimeout) {
    if (!this.adaptiveTimeouts) {
      return baseTimeout; // Return the standard timeout if adaptive is disabled
    }
    
    // Apply multiplier based on target response category
    let multiplier = this.timeoutMultipliers[this.targetResponseCategory];
    
    // Operation-specific adjustments
    switch (operation) {
      case 'port':
        // Port scans need more time on slow targets
        if (this.targetResponseCategory === 'slow') {
          multiplier = 1.75;
        }
        break;
      case 'http':
        // HTTP tends to be more consistent
        break;
      case 'nuclei':
        // Nuclei needs much more time on slow targets
        if (this.targetResponseCategory === 'slow') {
          multiplier = 2.0;
        }
        break;
    }
    
    // Calculate remaining time based on overall timeout
    if (this.scanStartTime) {
      const elapsedMs = Date.now() - this.scanStartTime;
      const remainingMs = this.overallTimeout - elapsedMs;
      
      // Ensure we don't exceed remaining time, with a 10% buffer
      return Math.min(baseTimeout * multiplier, remainingMs * 0.9);
    }
    
    return baseTimeout * multiplier;
  }

  /**
   * Classify an error into a standardized type
   * @param {Error} error - The error to classify
   * @returns {string} Standardized error type
   */
  classifyError(error) {
    const errorMsg = error.message ? error.message.toLowerCase() : '';
    const errorStack = error.stack ? error.stack.toLowerCase() : '';
    
    // Network errors
    if (errorMsg.includes('etimedout') || errorMsg.includes('timeout')) {
      return 'TIMEOUT';
    } else if (errorMsg.includes('econnrefused') || errorMsg.includes('connection refused')) {
      return 'CONNECTION_REFUSED';
    } else if (errorMsg.includes('econnreset') || errorMsg.includes('connection reset')) {
      return 'CONNECTION_RESET';
    } else if (errorMsg.includes('enotfound') || errorMsg.includes('not found')) {
      return 'HOST_NOT_FOUND';
    } else if (errorMsg.includes('network') || errorMsg.includes('network error')) {
      return 'NETWORK_ERROR';
    }
    
    // Firewall/Security errors
    if (errorMsg.includes('firewall') || 
        errorMsg.includes('blocked') || 
        errorMsg.includes('waf') ||
        errorMsg.includes('forbidden') ||
        errorMsg.includes('403')) {
      return 'FIREWALL_BLOCK';
    }
    
    // Authentication errors
    if (errorMsg.includes('authentication') || 
        errorMsg.includes('unauthorized') ||
        errorMsg.includes('401')) {
      return 'AUTHENTICATION_ERROR';
    }
    
    // Timeout specific errors
    if (errorMsg.includes('timed out') || 
        errorStack.includes('timeout')) {
      return 'TIMEOUT';
    }
    
    // Process errors
    if (errorMsg.includes('process') && 
        (errorMsg.includes('exit') || errorMsg.includes('killed'))) {
      return 'PROCESS_ERROR';
    }
    
    // Configuration errors
    if (errorMsg.includes('configuration') || 
        errorMsg.includes('config') || 
        errorMsg.includes('not installed') ||
        errorMsg.includes('not found in path')) {
      return 'CONFIGURATION_ERROR';
    }
    
    // Rate limiting
    if (errorMsg.includes('rate') && 
        (errorMsg.includes('limit') || errorMsg.includes('exceeded'))) {
      return 'RATE_LIMIT_EXCEEDED';
    }
    
    return 'UNKNOWN_ERROR';
  }

  /**
   * Parse a URL or hostname into components
   * @param {string} target - URL or hostname to scan
   * @returns {Object} Parsed URL information
   */
  parseTarget(target) {
    try {
      // If target doesn't have a protocol, add http:// so URL parsing works
      if (!target.match(/^[a-zA-Z]+:\/\//)) {
        target = 'http://' + target;
      }

      const parsedUrl = new URL(target);
      return {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80'),
        protocol: parsedUrl.protocol.replace(':', ''),
        path: parsedUrl.pathname,
        originalUrl: target
      };
    } catch (error) {
      throw new Error(`Invalid URL or hostname: ${target}`);
    }
  }

  /**
   * Perform port and service scanning on a target with advanced Nmap options
   * @param {string} target - URL or hostname to scan
   * @param {Object} options - Optional override options for this scan
   * @returns {Promise<Object>} Scan results
   */
  async scanPorts(target, options = {}) {
    const { hostname } = this.parseTarget(target);
    const scanType = options.scanType || (this.aggressive ? 'aggressive' : 'standard');
    const scanProtocol = options.protocol || 'tcp';
    const tcpScanMethod = options.tcpScanMethod || 'syn'; // syn or connect
    
    return new Promise((resolve, reject) => {
      let scanOptions = [];
      
      // First, set the scan method - TCP (SYN or Connect) or UDP
      if (scanProtocol === 'udp') {
        scanOptions.push('-sU'); // UDP scan
        console.log('Performing UDP scan');
      } else if (tcpScanMethod === 'connect') {
        scanOptions.push('-sT'); // TCP connect scan (more likely to work through firewalls)
        console.log('Performing TCP connect scan');
      } else {
        scanOptions.push('-sS'); // Default SYN stealth scan
        console.log('Performing TCP SYN scan');
      }
      
      // Select scan type based on configuration and context
      switch (scanType) {
        case 'aggressive':
          // Aggressive scan with version detection, OS detection
          scanOptions.push(
            '-sV',                  // Service/version detection
            '-O',                   // OS detection
            '--version-all',        // Try every probe for version detection
            '-p', this.ports,       // Target ports
            '--min-parallelism=10'  // Increase parallel probe operations
          );
          break;
          
        case 'stealth':
          // Stealthy scan focused on evasion
          scanOptions.push(
            '-sV',                  // Service/version detection
            '-p', this.ports,       // Target ports
            '--data-length=24',     // Add random data to packets to avoid detection
            '--randomize-hosts',    // Scan ports in random order
            '--spoof-mac=0'         // Randomize MAC address if possible
          );
          break;
          
        case 'script':
          // Script-focused scan with banner grabbing and HTTP header analysis
          scanOptions.push(
            '-sV',                  // Service/version detection 
            '-p', this.ports,       // Target ports
            '--script=banner,http-headers,http-title,ssl-enum-ciphers' // Run specific scripts
          );
          break;
          
        case 'quick':
          // Fast scan with minimal footprint
          scanOptions.push(
            '-F',                   // Fast scan - fewer ports
            '--min-rate=300'        // Send packets no slower than 300 per second
          );
          break;
          
        case 'standard':
        default:
          // Standard scan with better options than the original
          scanOptions.push(
            '-sV',                  // Service/version detection
            '-p', this.ports,       // Target ports
            '--version-intensity=7' // More intensive version detection (0-9 scale)
          );
          break;
      }
      
      // Add -Pn flag to skip host discovery (assume host is up)
      // This helps with hosts that block ping probes
      scanOptions.push('-Pn');
      
      // Add host-timeout parameter to limit how long nmap spends on a single host
      const adaptiveNmapTimeout = this.calculateAdaptiveTimeout('port', this.portScanTimeout);
      const hostTimeoutSec = Math.floor(adaptiveNmapTimeout / 1000);
      scanOptions.push('--host-timeout', `${hostTimeoutSec}s`);
      
      // Add max-retries parameter to limit retries on unresponsive ports
      scanOptions.push('--max-retries', '2');
      
      // Use timing template based on response profile
      let timingTemplate = '3'; // Default is T3 (normal)
      if (this.targetResponseCategory === 'slow') {
        timingTemplate = '2'; // T2 (sneaky) for slow targets to avoid overloading
      } else if (this.targetResponseCategory === 'responsive') {
        timingTemplate = '4'; // T4 (aggressive) for responsive targets
      }
      scanOptions.push(`-T${timingTemplate}`);
      
      console.log(`Starting Nmap scan on ${hostname} with options: ${scanOptions.join(' ')}`);
      console.log(`Using adaptive timeout: ${adaptiveNmapTimeout}ms (${hostTimeoutSec}s)`);
      
      const scan = new nmap.NmapScan(hostname, scanOptions);
      
      // Setup timeout with adaptive calculation
      const timeoutId = setTimeout(() => {
        console.log(`Nmap scan timeout after ${adaptiveNmapTimeout}ms, cancelling scan...`);
        scan.cancelScan();
        
        // Instead of silently resolving, reject with proper timeout error
        const timeoutError = new Error(`Nmap scan timed out after ${adaptiveNmapTimeout}ms`);
        timeoutError.code = 'ETIMEDOUT';
        timeoutError.errorType = 'SCAN_TIMEOUT';
        reject(timeoutError);
      }, adaptiveNmapTimeout);
      
      scan.on('complete', (data) => {
        clearTimeout(timeoutId);
        console.log(`Nmap scan completed successfully for ${hostname}`);
        resolve(this.formatPortResults(data, scanProtocol));
      });
      
      scan.on('error', (error) => {
        clearTimeout(timeoutId);
        console.error(`Nmap error: ${error.toString()}`);
        // Instead of silently returning an empty array, provide error information
        const errorObj = new Error(`Nmap scan failed: ${error.toString()}`);
        errorObj.code = error.code || 'NMAP_ERROR';
        errorObj.originalError = error;
        
        // Categorize common nmap errors
        if (error.toString().includes('permission')) {
          errorObj.errorType = 'PERMISSION_DENIED';
        } else if (error.toString().includes('not found') || error.toString().includes('not installed')) {
          errorObj.errorType = 'NMAP_NOT_INSTALLED';
        } else if (error.toString().includes('timed out') || error.toString().includes('timeout')) {
          errorObj.errorType = 'SCAN_TIMEOUT';
        } else if (error.toString().includes('firewall') || error.toString().includes('blocked')) {
          errorObj.errorType = 'FIREWALL_BLOCK';
        } else {
          errorObj.errorType = 'NMAP_ERROR';
        }
        
        reject(errorObj);
      });
      
      try {
        scan.startScan();
      } catch (error) {
        clearTimeout(timeoutId);
        console.error(`Failed to start Nmap scan: ${error.toString()}`);
        // Instead of rejecting with error, resolve with empty result
        resolve([]);
      }
    });
  }

  /**
   * Run a service-specific Nmap script scan on an open port
   * This enhances port information with additional service details
   * 
   * @param {string} hostname - Target hostname
   * @param {number} port - Target port
   * @param {string} service - Detected service name
   * @returns {Promise<Object>} Enhanced service information
   */
  async runServiceScripts(hostname, port, service) {
    // Skip if port or service is invalid
    if (!port || !service || service === 'unknown') {
      return null;
    }
    
    // Select scripts based on service
    let scripts = [];
    switch (service.toLowerCase()) {
      case 'http':
      case 'https':
        scripts = ['http-headers', 'http-title', 'http-server-header', 'http-methods', 'http-generator'];
        break;
      case 'ssh':
        scripts = ['ssh-auth-methods', 'ssh-hostkey', 'ssh2-enum-algos'];
        break;
      case 'ftp':
        scripts = ['ftp-anon', 'ftp-bounce', 'ftp-syst'];
        break;
      case 'smtp':
        scripts = ['smtp-commands', 'smtp-enum-users', 'smtp-open-relay'];
        break;
      case 'mysql':
      case 'ms-sql':
      case 'oracle':
        scripts = ['mysql-info', 'ms-sql-info', 'oracle-tns-info'];
        break;
      default:
        scripts = ['banner'];
        break;
    }
    
    return new Promise((resolve, reject) => {
      const scriptParam = scripts.join(',');
      const scanOptions = [
        '-sS',                // SYN stealth scan
        '-Pn',                // Skip host discovery
        '-p', port.toString(),  // Specific port
        '--script', scriptParam, // Selected scripts
        '-T2'                 // Timing template (sneaky)
      ];
      
      console.log(`Running service scripts on ${hostname}:${port} (${service}): ${scriptParam}`);
      
      const scan = new nmap.NmapScan(hostname, scanOptions);
      
      const scriptTimeout = 30000; // 30 seconds timeout for script scanning
      const timeoutId = setTimeout(() => {
        console.log(`Script scan timeout after ${scriptTimeout}ms, cancelling scan...`);
        scan.cancelScan();
        resolve(null); // Resolve with null on timeout (non-critical)
      }, scriptTimeout);
      
      scan.on('complete', (data) => {
        clearTimeout(timeoutId);
        
        // Extract script results
        let scriptResults = {};
        try {
          if (data && data.length > 0 && data[0].openPorts && data[0].openPorts.length > 0) {
            const portData = data[0].openPorts[0];
            
            // Extract script results if available
            if (portData.scripts) {
              scriptResults = portData.scripts.reduce((acc, script) => {
                acc[script.name] = script.result;
                return acc;
              }, {});
            }
            
            // Extract other port information
            if (portData.service) scriptResults.service = portData.service;
            if (portData.version) scriptResults.version = portData.version;
            if (portData.banner) scriptResults.banner = portData.banner;
          }
        } catch (err) {
          console.error(`Error processing script results: ${err.message}`);
        }
        
        resolve(scriptResults);
      });
      
      scan.on('error', (error) => {
        clearTimeout(timeoutId);
        console.error(`Script scan error: ${error.toString()}`);
        resolve(null); // Resolve with null on error (non-critical)
      });
      
      try {
        scan.startScan();
      } catch (error) {
        clearTimeout(timeoutId);
        console.error(`Failed to start script scan: ${error.toString()}`);
        resolve(null);
      }
    });
  }

  /**
   * Format port scanning results with enhanced information
   * @param {Array} data - Raw nmap scan results
   * @param {string} scanProtocol - The protocol used in scanning (tcp or udp)
   * @returns {Array} Formatted port results
   */
  formatPortResults(data, scanProtocol = 'tcp') {
    if (!data || !data.length || !data[0] || !data[0].openPorts) {
      return [];
    }

    return data[0].openPorts.map(port => {
      // Extract any script results if available
      const scriptData = port.scripts ? port.scripts.reduce((acc, script) => {
        acc[script.name] = script.result;
        return acc;
      }, {}) : {};
      
      return {
        port: port.port,
        protocol: port.protocol || scanProtocol,
        service: port.service || 'unknown',
        version: port.version || '',
        state: 'open',
        banner: port.banner || '',
        script_results: Object.keys(scriptData).length > 0 ? scriptData : undefined
      };
    });
  }

  /**
   * Analyze HTTP headers for a web server with adaptive timeout handling
   * @param {string} target - URL to analyze
   * @returns {Promise<Object>} Header analysis results
   */
  async analyzeHttpHeaders(target) {
    const { protocol, hostname, port, path } = this.parseTarget(target);
    const url = `${protocol}://${hostname}${port ? ':' + port : ''}${path || '/'}`;
    
    // Calculate adaptive timeout for HTTP operations
    const adaptiveTimeout = this.calculateAdaptiveTimeout('http', this.timeout);
    console.log(`HTTP analysis for ${url} with adaptive timeout: ${adaptiveTimeout}ms`);
    
    try {
      const response = await axios.get(url, {
        timeout: adaptiveTimeout,
        maxRedirects: 2,
        validateStatus: () => true, // Accept any status code
        headers: {
          'User-Agent': 'NetSage-Scanner/1.0',
          // Add extra headers to avoid detection as a scanner
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'gzip, deflate, br'
        }
      });

      return {
        statusCode: response.status,
        statusMessage: response.statusText,
        headers: response.headers,
        server: response.headers.server || 'unknown',
        contentType: response.headers['content-type'] || 'unknown',
        securityHeaders: this.analyzeSecurityHeaders(response.headers)
      };
    } catch (error) {
      if (error.response) {
        // The request was made and the server responded with a status code
        // that falls out of the range of 2xx
        return {
          statusCode: error.response.status,
          statusMessage: error.response.statusText,
          headers: error.response.headers,
          server: error.response.headers.server || 'unknown',
          contentType: error.response.headers['content-type'] || 'unknown',
          securityHeaders: this.analyzeSecurityHeaders(error.response.headers),
          error: `HTTP request failed with status ${error.response.status}`
        };
      } else if (error.request) {
        // The request was made but no response was received
        return {
          error: 'No response received from server',
          message: error.message
        };
      } else {
        // Something happened in setting up the request that triggered an Error
        return {
          error: 'HTTP request configuration failed',
          message: error.message
        };
      }
    }
  }

  /**
   * Analyze security headers from HTTP response
   * @param {Object} headers - HTTP response headers
   * @returns {Object} Security header analysis
   */
  analyzeSecurityHeaders(headers) {
    const headersLower = {};
    // Convert all header names to lowercase for case-insensitive checks
    Object.keys(headers).forEach(key => {
      headersLower[key.toLowerCase()] = headers[key];
    });
    
    return {
      hasStrictTransportSecurity: 'strict-transport-security' in headersLower,
      hasContentSecurityPolicy: 'content-security-policy' in headersLower,
      hasXContentTypeOptions: 'x-content-type-options' in headersLower,
      hasXFrameOptions: 'x-frame-options' in headersLower,
      hasXXSSProtection: 'x-xss-protection' in headersLower,
      hasReferrerPolicy: 'referrer-policy' in headersLower,
      hasPermissionsPolicy: 'permissions-policy' in headersLower || 'feature-policy' in headersLower,
      strictTransportSecurityValue: headersLower['strict-transport-security'] || null,
      contentSecurityPolicyValue: headersLower['content-security-policy'] || null,
      xContentTypeOptionsValue: headersLower['x-content-type-options'] || null,
      xFrameOptionsValue: headersLower['x-frame-options'] || null,
      xxssProtectionValue: headersLower['x-xss-protection'] || null,
      referrerPolicyValue: headersLower['referrer-policy'] || null,
      permissionsPolicyValue: headersLower['permissions-policy'] || headersLower['feature-policy'] || null
    };
  }

  /**
   * Perform a Nuclei vulnerability scan with enhanced timeout handling
   * @param {string} target - URL to scan
   * @returns {Promise<Object>} Nuclei scan results
   */
  async runNucleiScan(target) {
    if (!this.enableNuclei || !this.nucleiScanner) {
      return { enabled: false };
    }
    
    try {
      // Calculate adaptive timeout for Nuclei based on target response
      let nucleiTimeout = this.nucleiScanner.timeout;  // Get the base timeout
      
      if (this.adaptiveTimeouts) {
        // Calculate remaining time and adjust Nuclei timeout
        const elapsedMs = Date.now() - this.scanStartTime;
        const remainingMs = this.overallTimeout - elapsedMs;
        
        // Ensure we leave at least 10% of the overall timeout for cleanup
        const maxNucleiTime = Math.max(remainingMs * 0.9, 60000);  // At least 1 minute
        
        // Apply adaptive factors
        const adaptiveTime = this.calculateAdaptiveTimeout('nuclei', nucleiTimeout);
        
        // Use the smaller of calculated time and max available time
        nucleiTimeout = Math.min(adaptiveTime, maxNucleiTime);
        
        console.log(`Adjusted Nuclei timeout to ${nucleiTimeout}ms based on target response and remaining time`);
        
        // Update the nucleiScanner timeout
        this.nucleiScanner.timeout = nucleiTimeout;
      }
      
      console.log(`Starting Nuclei scan for ${target} with ${nucleiTimeout}ms timeout`);
      const results = await this.nucleiScanner.scan(target);
      console.log(`Completed Nuclei scan for ${target}: found ${results.findings?.length || 0} findings`);
      return results;
    } catch (error) {
      console.error(`Error in Nuclei scan: ${error.message}`);
      
      // Enhance error information
      const errorType = this.classifyError(error);
      return {
        enabled: true,
        success: false,
        error: error.message,
        error_type: errorType,
        time_of_failure: new Date().toISOString(),
        findings: []
      };
    }
  }

  /**
   * Perform a comprehensive scan on a target with enhanced timeout management
   * @param {string} target - URL or hostname to scan
   * @returns {Promise<Object>} Complete scan results
   */
  /**
   * Run a UDP scan to find services that use UDP protocol
   * @param {string} target - Target to scan
   * @param {Object} options - Scan options
   * @returns {Promise<Array>} UDP port results
   */
  async scanUdpPorts(target, options = {}) {
    if (!this.enableUdpScan) {
      console.log('UDP scanning is disabled, skipping');
      return [];
    }
    
    console.log(`Starting UDP scan on ${target}`);
    const scanType = options.scanType || 'quick'; // Use quick scan for UDP by default
    
    return this.scanPorts(target, {
      scanType: scanType,
      protocol: 'udp',
      ports: this.udpPorts
    });
  }

  async scan(target) {
    try {
      // Record start time for overall timeout management
      this.scanStartTime = Date.now();
      const startTime = this.scanStartTime;
      const { hostname, protocol } = this.parseTarget(target);
      
      // Determine target responsiveness with a quick HTTP ping
      // This helps calibrate our adaptive timeouts
      if (this.adaptiveTimeouts && protocol.startsWith('http')) {
        try {
          console.log(`Performing responsiveness check for ${target}...`);
          const pingStart = Date.now();
          const pingResponse = await axios.get(target, { 
            timeout: 5000, 
            maxRedirects: 1,
            validateStatus: () => true 
          });
          const pingDuration = Date.now() - pingStart;
          
          // Categorize based on response time
          if (pingDuration < 1000) {
            this.targetResponseCategory = 'responsive';
            console.log(`Target ${target} is responsive (${pingDuration}ms)`);
          } else if (pingDuration > 3000) {
            this.targetResponseCategory = 'slow';
            console.log(`Target ${target} is slow (${pingDuration}ms)`);
          } else {
            this.targetResponseCategory = 'normal';
            console.log(`Target ${target} has normal response time (${pingDuration}ms)`);
          }
        } catch (pingError) {
          console.log(`Responsiveness check failed for ${target}: ${pingError.message}`);
          this.targetResponseCategory = 'slow'; // Assume slow when ping fails
        }
      }
      
      // Set up a Promise.race with an overall timeout
      const overallTimeoutPromise = new Promise((_, reject) => {
        setTimeout(() => {
          reject(new Error(`Overall scan timeout reached (${this.overallTimeout}ms)`));
        }, this.overallTimeout);
      });
      
      // Primary scan Promise
      const scanPromise = (async () => {
        // Select the appropriate scan type based on target and response category
        let initialScanType = this.aggressive ? 'aggressive' : 'standard';
        
        // If target seems protected or slow, start with a more stealthy scan
        if (this.targetResponseCategory === 'slow') {
          initialScanType = 'stealth';
        }
        
        // Run port scanning and HTTP header analysis in parallel
        const scanPromises = [
          this.scanPorts(target, { scanType: initialScanType }),
          protocol.startsWith('http') ? this.analyzeHttpHeaders(target) : Promise.resolve(null)
        ];
        
        // Add Nuclei scan if enabled
        if (this.enableNuclei && protocol.startsWith('http')) {
          scanPromises.push(this.runNucleiScan(target));
        } else {
          scanPromises.push(Promise.resolve({ enabled: false }));
        }
        
        // Wait for the initial scans to complete
        const initialResults = await Promise.allSettled(scanPromises);
        const [portResults, httpResults, nucleiResults] = initialResults;
        
        // Port scan fallback strategies
        let allPortResults = [];
        
        // If the initial scan failed completely or found no ports, try additional strategies
        if (portResults.status === 'rejected' || 
           (portResults.status === 'fulfilled' && (!portResults.value || portResults.value.length === 0))) {
          
          console.log('Initial TCP scan did not find results, trying fallback strategies...');
          let fallbackResults = [];
          
          // Try script scan first as a fallback
          if (this.targetResponseCategory !== 'slow') {
            console.log('Trying script-based scan...');
            try {
              fallbackResults = await this.scanPorts(target, { scanType: 'script' });
              if (fallbackResults && fallbackResults.length > 0) {
                console.log(`Script scan found ${fallbackResults.length} open ports`);
                allPortResults = allPortResults.concat(fallbackResults);
              }
            } catch (scriptError) {
              console.error('Script scan failed:', scriptError.message);
            }
          }
          
          // If still no results or script scan failed, try TCP connect scan
          if (allPortResults.length === 0) {
            console.log('Trying TCP connect scan...');
            try {
              fallbackResults = await this.scanPorts(target, { 
                scanType: 'standard', 
                tcpScanMethod: 'connect' // Use TCP connect scan instead of SYN
              });
              if (fallbackResults && fallbackResults.length > 0) {
                console.log(`TCP connect scan found ${fallbackResults.length} open ports`);
                allPortResults = allPortResults.concat(fallbackResults);
              }
            } catch (connectError) {
              console.error('TCP connect scan failed:', connectError.message);
            }
          }
          
          // If still nothing, try a quick scan
          if (allPortResults.length === 0) {
            console.log('Trying quick scan...');
            try {
              fallbackResults = await this.scanPorts(target, { scanType: 'quick' });
              if (fallbackResults && fallbackResults.length > 0) {
                console.log(`Quick scan found ${fallbackResults.length} open ports`);
                allPortResults = allPortResults.concat(fallbackResults);
              }
            } catch (quickError) {
              console.error('Quick scan failed:', quickError.message);
            }
          }
          
          // If original port scan was fulfilled but empty, update it with our fallback results
          if (portResults.status === 'fulfilled') {
            portResults.value = allPortResults;
          }
        } else if (portResults.status === 'fulfilled') {
          // If original scan was successful, use those results as the base
          allPortResults = portResults.value;
        }
        // Add UDP scanning to complement TCP scanning
        let udpResults = [];
        try {
          // Only perform UDP scanning if we have TCP results or we're desperate for results
          if (allPortResults.length > 0 || this.aggressive) {
            console.log('Performing UDP port scan for complementary services...');
            udpResults = await this.scanUdpPorts(target);
            if (udpResults && udpResults.length > 0) {
              console.log(`UDP scan found ${udpResults.length} open ports`);
              // Add UDP ports to the overall results
              allPortResults = allPortResults.concat(udpResults);
            }
          }
        } catch (udpError) {
          console.error('UDP scan failed:', udpError.message);
        }
        
        // Update portResults.value with all accumulated port results
        if (portResults.status === 'fulfilled') {
          portResults.value = allPortResults;
        }
        
        // Run service-specific script scans if we found ports
        if (allPortResults.length > 0) {
          // Only scan the first 3 ports to avoid taking too long
          const portsToScan = allPortResults.slice(0, 3);
          const scriptPromises = [];
          
          for (const port of portsToScan) {
            const scriptPromise = this.runServiceScripts(hostname, port.port, port.service)
              .then(scriptResults => {
                if (scriptResults) {
                  // Enhance the port object with script results
                  port.script_results = scriptResults;
                  
                  // Update service and version if more specific info found
                  if (scriptResults.service && scriptResults.service !== 'unknown') {
                    port.service = scriptResults.service;
                  }
                  if (scriptResults.version) {
                    port.version = scriptResults.version;
                  }
                  if (scriptResults.banner) {
                    port.banner = scriptResults.banner;
                  }
                }
                return port;
              });
            
            scriptPromises.push(scriptPromise);
          }
          
          // Wait for service script scans to complete
          console.log(`Running service-specific script scans for ${scriptPromises.length} ports...`);
          await Promise.allSettled(scriptPromises);
        }
        
        return [portResults, httpResults, nucleiResults];
      })();
      
      // Race between the scan completing and the overall timeout
      const results = await Promise.race([
        scanPromise,
        overallTimeoutPromise
      ]);
      
      const [portResults, httpResults, nucleiResults] = results;

      // Calculate scan duration
      const scanDuration = Date.now() - startTime;

      // Format the results
      const result = {
        target: {
          original: target,
          hostname: hostname,
          protocol: protocol
        },
        scanTimestamp: new Date().toISOString(),
        scanDurationMs: scanDuration,
        ports: portResults.status === 'fulfilled' ? portResults.value : [],
        http: httpResults.status === 'fulfilled' ? httpResults.value : null,
        nuclei: nucleiResults.status === 'fulfilled' ? nucleiResults.value : { enabled: false },
        errors: [],
        // Add enhanced error tracking
        scan_status: {
          port_scan: {
            success: portResults.status === 'fulfilled',
            error_type: portResults.status === 'rejected' ? this.classifyError(portResults.reason) : null,
            message: portResults.status === 'rejected' ? portResults.reason.message : null,
            results_found: portResults.status === 'fulfilled' && portResults.value.length > 0
          },
          http_analysis: {
            success: httpResults.status === 'fulfilled',
            error_type: httpResults.status === 'rejected' ? this.classifyError(httpResults.reason) : null,
            message: httpResults.status === 'rejected' ? httpResults.reason.message : null,
            results_found: httpResults.status === 'fulfilled' && httpResults.value !== null && 
                         !httpResults.value.error
          },
          vulnerability_scan: {
            success: nucleiResults.status === 'fulfilled',
            error_type: nucleiResults.status === 'rejected' ? this.classifyError(nucleiResults.reason) : null,
            message: nucleiResults.status === 'rejected' ? nucleiResults.reason.message : null,
            results_found: nucleiResults.status === 'fulfilled' && 
                         nucleiResults.value.findings && 
                         nucleiResults.value.findings.length > 0
          }
        }
      };

      // Add any errors that occurred during scanning (keep original error format for backward compatibility)
      if (portResults.status === 'rejected') {
        result.errors.push({
          component: 'port_scanner',
          message: portResults.reason.message,
          error_type: this.classifyError(portResults.reason),
          time_of_failure: new Date().toISOString()
        });
      } else if (portResults.status === 'fulfilled' && portResults.value.length === 0) {
        // Add information when port scan succeeded but found no open ports
        result.errors.push({
          component: 'port_scanner',
          message: 'No open ports detected. Target may have firewall or no services running.',
          error_type: 'NO_RESULTS',
          time_of_failure: new Date().toISOString()
        });
      }

      if (httpResults.status === 'rejected' && protocol.startsWith('http')) {
        result.errors.push({
          component: 'http_analyzer',
          message: httpResults.reason.message,
          error_type: this.classifyError(httpResults.reason),
          time_of_failure: new Date().toISOString()
        });
      } else if (httpResults.status === 'fulfilled' && httpResults.value && httpResults.value.error) {
        // Add HTTP errors that were returned in the value
        result.errors.push({
          component: 'http_analyzer',
          message: httpResults.value.message || httpResults.value.error,
          error_type: 'HTTP_ERROR',
          status_code: httpResults.value.statusCode,
          time_of_failure: new Date().toISOString()
        });
      }
      
      if (nucleiResults.status === 'rejected' && this.enableNuclei && protocol.startsWith('http')) {
        result.errors.push({
          component: 'nuclei_scanner',
          message: nucleiResults.reason.message,
          error_type: this.classifyError(nucleiResults.reason),
          time_of_failure: new Date().toISOString()
        });
      } else if (nucleiResults.status === 'fulfilled' && 
                nucleiResults.value && 
                nucleiResults.value.error) {
        // Add Nuclei errors that were returned in the value
        result.errors.push({
          component: 'nuclei_scanner',
          message: nucleiResults.value.error,
          error_type: 'NUCLEI_ERROR',
          time_of_failure: new Date().toISOString()
        });
      }

      return result;
    } catch (error) {
      const errorType = this.classifyError(error);
      return {
        target: {
          original: target,
          hostname: typeof target === 'string' ? target.replace(/^https?:\/\//, '').split('/')[0] : 'unknown',
          protocol: target.includes('https://') ? 'https' : 'http'
        },
        scanTimestamp: new Date().toISOString(),
        scanDurationMs: Date.now() - startTime,
        ports: [],
        http: null,
        nuclei: { enabled: this.enableNuclei, success: false },
        errors: [{
          component: 'scanner',
          message: error.message,
          error_type: errorType,
          time_of_failure: new Date().toISOString(),
          stack_trace: process.env.NODE_ENV !== 'production' ? error.stack : undefined
        }],
        scan_status: {
          port_scan: { success: false, error_type: errorType, message: error.message },
          http_analysis: { success: false, error_type: errorType, message: error.message },
          vulnerability_scan: { success: false, error_type: errorType, message: error.message }
        }
      };
    }
  }
}

module.exports = Scanner;
