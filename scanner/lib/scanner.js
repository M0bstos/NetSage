/**
 * Scanner Core Module
 * 
 * This module implements the core scanning functionality for the NetSage website scanner.
 * It performs port scanning, service detection, version detection, and HTTP header analysis.
 */

const nmap = require('node-nmap');
const axios = require('axios');
const { URL } = require('url');

// Configure nmap path if necessary
// nmap.nmapLocation = 'path/to/nmap'; // Uncomment and set if nmap is not in PATH

class Scanner {
  /**
   * Creates a new scanner instance
   * @param {Object} options - Scanner options
   * @param {number} options.timeout - Timeout in milliseconds for scan operations
   * @param {string} options.ports - Comma-separated list of ports to scan
   * @param {boolean} options.aggressive - Whether to use aggressive scanning techniques
   */
  constructor(options = {}) {
    this.timeout = options.timeout || 30000; // Default 30 seconds
    this.ports = options.ports || '21,22,25,80,443,3306,8080,8443';
    this.aggressive = options.aggressive || false;
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
   * Perform port and service scanning on a target
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
      
      const scan = new nmap.NmapScan(hostname, scanOptions);
      
      // Setup timeout
      const timeoutId = setTimeout(() => {
        scan.cancelScan();
        reject(new Error(`Scan timeout after ${this.timeout}ms`));
      }, this.timeout);
      
      scan.on('complete', (data) => {
        clearTimeout(timeoutId);
        resolve(this.formatPortResults(data));
      });
      
      scan.on('error', (error) => {
        clearTimeout(timeoutId);
        reject(new Error(`Port scan error: ${error.toString()}`));
      });
      
      try {
        scan.startScan();
      } catch (error) {
        clearTimeout(timeoutId);
        reject(new Error(`Failed to start scan: ${error.toString()}`));
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
   * Analyze HTTP headers for a web server
   * @param {string} target - URL to analyze
   * @returns {Promise<Object>} Header analysis results
   */
  async analyzeHttpHeaders(target) {
    const { protocol, hostname, port, path } = this.parseTarget(target);
    const url = `${protocol}://${hostname}${port ? ':' + port : ''}${path || '/'}`;
    
    try {
      const response = await axios.get(url, {
        timeout: this.timeout,
        maxRedirects: 2,
        validateStatus: () => true, // Accept any status code
        headers: {
          'User-Agent': 'NetSage-Scanner/1.0'
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
   * Perform a comprehensive scan on a target
   * @param {string} target - URL or hostname to scan
   * @returns {Promise<Object>} Complete scan results
   */
  async scan(target) {
    try {
      const startTime = Date.now();
      const { hostname, protocol } = this.parseTarget(target);
      
      // Run port scanning and HTTP header analysis in parallel
      const [portResults, httpResults] = await Promise.allSettled([
        this.scanPorts(target),
        protocol.startsWith('http') ? this.analyzeHttpHeaders(target) : Promise.resolve(null)
      ]);

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
        errors: []
      };

      // Add any errors that occurred during scanning
      if (portResults.status === 'rejected') {
        result.errors.push({
          component: 'port_scanner',
          message: portResults.reason.message
        });
      }

      if (httpResults.status === 'rejected' && protocol.startsWith('http')) {
        result.errors.push({
          component: 'http_analyzer',
          message: httpResults.reason.message
        });
      }

      return result;
    } catch (error) {
      return {
        target: target,
        scanTimestamp: new Date().toISOString(),
        errors: [{
          component: 'scanner',
          message: error.message
        }],
        ports: [],
        http: null
      };
    }
  }
}

module.exports = Scanner;
