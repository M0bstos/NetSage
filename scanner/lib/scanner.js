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
   * Perform port and service scanning on a target with enhanced timeout handling
   * @param {string} target - URL or hostname to scan
   * @returns {Promise<Object>} Scan results
   */
  async scanPorts(target) {
    const { hostname } = this.parseTarget(target);
    
    return new Promise((resolve, reject) => {
      let scanOptions = [];
      
      if (this.aggressive) {
        // Aggressive scan with version detection and OS detection
        scanOptions = ['-sV', '-O', '--version-all', '-p', this.ports];
      } else {
        // Standard scan with basic version detection
        scanOptions = ['-sV', '-p', this.ports];
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
      let timingTemplate = '4'; // Default is T4 (aggressive)
      if (this.targetResponseCategory === 'slow') {
        timingTemplate = '3'; // T3 (normal) for slow targets to avoid overloading
      } else if (this.targetResponseCategory === 'responsive') {
        timingTemplate = '5'; // T5 (insane) for responsive targets
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
        resolve(this.formatPortResults(data));
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
   * Format port scanning results
   * @param {Array} data - Raw nmap scan results
   * @returns {Array} Formatted port results
   */
  formatPortResults(data) {
    if (!data || !data.length || !data[0] || !data[0].openPorts) {
      return [];
    }

    return data[0].openPorts.map(port => {
      return {
        port: port.port,
        protocol: port.protocol || 'tcp',
        service: port.service || 'unknown',
        version: port.version || '',
        state: 'open',
        banner: port.banner || ''
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
        // Run port scanning and HTTP header analysis in parallel
        const scanPromises = [
          this.scanPorts(target),
          protocol.startsWith('http') ? this.analyzeHttpHeaders(target) : Promise.resolve(null)
        ];
        
        // Add Nuclei scan if enabled
        if (this.enableNuclei && protocol.startsWith('http')) {
          scanPromises.push(this.runNucleiScan(target));
        } else {
          scanPromises.push(Promise.resolve({ enabled: false }));
        }
        
        // Wait for all scans to complete
        return await Promise.allSettled(scanPromises);
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
