/**
 * Scanner Core Module with Enhanced Port Detection
 * 
 * This module implements the core scanning functionality for the NetSage website scanner.
 * It performs port scanning, service detection, version detection, and HTTP header analysis.
 * It also integrates with Nuclei for vulnerability scanning.
 * 
 * Enhanced with improved port detection logic for Phase 2, Step 3.
 */

const nmap = require('node-nmap');
const axios = require('axios');
const { URL } = require('url');
const NucleiScanner = require('./nuclei');
const PortDetection = require('./portDetection');
const OutputFormatter = require('./utils/outputFormatter');
const ErrorHandler = require('./utils/errorHandler');
const EvasionTechniques = require('./utils/evasionTechniques');
const AlternativeDetection = require('./utils/alternativeDetection');
const ProxySupport = require('./utils/proxySupport');

// Configure nmap path if necessary
// nmap.nmapLocation = 'path/to/nmap'; // Uncomment and set if nmap is not in PATH

class Scanner {
  /**
   * Creates a new scanner instance with enhanced timeout handling and port detection
   * @param {Object} options - Scanner options
   * @param {number} options.timeout - General timeout in milliseconds for scan operations
   * @param {number} options.portScanTimeout - Specific timeout for port scanning operations
   * @param {number} options.overallTimeout - Maximum time for the entire scan process
   * @param {string} options.ports - Comma-separated list of ports to scan
   * @param {boolean} options.aggressive - Whether to use aggressive scanning techniques
   * @param {boolean} options.enableNuclei - Whether to enable Nuclei vulnerability scanning
   * @param {boolean} options.adaptiveTimeouts - Whether to use adaptive timeouts based on target response
   * @param {boolean} options.enablePortDetection - Whether to enable enhanced port detection
   * @param {boolean} options.enableBannerGrabbing - Whether to enable banner grabbing
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
    
    // Enhanced port detection options
    this.enablePortDetection = options.enablePortDetection !== false; // Enable port detection by default
    this.enableBannerGrabbing = options.enableBannerGrabbing !== false; // Enable banner grabbing by default
    
    // Phase 4, Step 1: Evasion technique options
    const evasionOptions = options.evasionOptions || {};
    this.enableEvasion = options.enableEvasion !== false; // Enable evasion by default
    this.evasionProfile = options.evasionProfile || 'moderate'; // Default to moderate evasion
    
    // Phase 4, Step 2: Alternative detection options
    const alternativeOptions = options.alternativeOptions || {};
    this.enableAlternativeDetection = options.enableAlternativeDetection !== false; // Enable alternative detection by default
    this.enableSSLAnalysis = alternativeOptions.enableSSLAnalysis !== false; // Enable SSL analysis by default
    this.enableHTTPFingerprinting = alternativeOptions.enableHTTPFingerprinting !== false; // Enable HTTP fingerprinting by default
    this.enableJSDetection = alternativeOptions.enableJSDetection !== false; // Enable JS/CSS detection by default
    
    // Phase 4, Step 3: Proxy support options
    const proxyOptions = options.proxyOptions || {};
    this.enableProxySupport = options.enableProxySupport !== false; // Enable proxy support by default
    this.proxyList = proxyOptions.proxyList || []; // List of proxy configurations
    this.enableTor = proxyOptions.enableTor !== false; // Enable TOR support by default
    this.rotateUserAgents = proxyOptions.rotateUserAgents !== false; // Enable user agent rotation by default
    this.enableConnectionPooling = proxyOptions.enableConnectionPooling !== false; // Enable connection pooling by default
    
    // Initialize helper modules
    this.portDetection = new PortDetection({
      timeout: this.timeout,
      enableBannerGrabbing: this.enableBannerGrabbing
    });
    
    this.outputFormatter = new OutputFormatter();
    this.errorHandler = new ErrorHandler();
    
    // Initialize evasion techniques module
    this.evasionTechniques = new EvasionTechniques({
      enableFragmentation: evasionOptions.enableFragmentation !== false,
      enableDecoys: evasionOptions.enableDecoys !== false,
      enableSourcePort: evasionOptions.enableSourcePort !== false,
      enableRandomization: evasionOptions.enableRandomization !== false
    });
    
    // Initialize proxy support module first
    this.proxySupport = new ProxySupport({
      proxyList: this.proxyList,
      enableTor: this.enableTor,
      rotateUserAgents: this.rotateUserAgents,
      enableConnectionPooling: this.enableConnectionPooling,
      maxPoolSize: proxyOptions.maxPoolSize || 10,
      poolTimeout: proxyOptions.poolTimeout || 30000,
      torProxy: proxyOptions.torProxy
    });
    
    // Initialize alternative detection module
    this.alternativeDetection = new AlternativeDetection({
      timeout: this.timeout,
      enableSSL: this.enableSSLAnalysis,
      enableHTTP: this.enableHTTPFingerprinting,
      enableJS: this.enableJSDetection,
      userAgent: options.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/107.0.0.0 Safari/537.36',
      // Pass proxy-enabled request function if available
      customRequestFunction: this.enableProxySupport ? this.proxySupport.makeProxiedRequest.bind(this.proxySupport) : null
    });
    
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
    
    if (this.enableEvasion) {
      console.log(`Evasion techniques enabled with profile: ${this.evasionProfile}`);
    }
    
    if (this.enableAlternativeDetection) {
      console.log(`Alternative detection methods enabled: SSL=${this.enableSSLAnalysis}, HTTP=${this.enableHTTPFingerprinting}, JS/CSS=${this.enableJSDetection}`);
    }
    
    if (this.enableProxySupport) {
      console.log(`Proxy support enabled: Proxies=${this.proxyList.length}, TOR=${this.enableTor}, User-Agent Rotation=${this.rotateUserAgents}, Connection Pooling=${this.enableConnectionPooling}`);
    }
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
      const elapsedTime = Date.now() - this.scanStartTime;
      const remainingTime = this.overallTimeout - elapsedTime;
      
      // Ensure we don't exceed the remaining time
      const maxTimeout = remainingTime * 0.8; // Use at most 80% of remaining time
      
      // Return the smaller of the adaptive timeout and max timeout
      return Math.min(baseTimeout * multiplier, maxTimeout);
    }
    
    return baseTimeout * multiplier;
  }
  
  /**
   * Check target responsiveness to adjust timeouts
   * @param {string} hostname - The hostname to check
   * @returns {Promise<string>} - The responsiveness category ('responsive', 'normal', 'slow')
   */
  async checkTargetResponsiveness(hostname) {
    try {
      console.log(`Performing responsiveness check for ${hostname}...`);
      
      // For simplicity, we'll just try a quick HTTP request
      // In a real implementation, you might do a more sophisticated ping or traceroute
      const startTime = Date.now();
      
      try {
        // Try a simple HTTP request with a short timeout using proxy support if enabled
        let response;
        if (this.enableProxySupport) {
          response = await this.proxySupport.makeProxiedRequest(`http://${hostname}`, {
            maxRetries: 1,
            retryDelay: 500,
            fallbackToNoProxy: true
          });
        } else {
          response = await axios.get(`http://${hostname}`, {
            timeout: 3000,
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/96.0.4664.110 Safari/537.36'
            }
          });
        }
        
        // Calculate response time
        const responseTime = Date.now() - startTime;
        
        // Categorize based on response time
        if (responseTime < 500) {
          this.targetResponseCategory = 'responsive';
          console.log(`Target ${hostname} is responsive (${responseTime}ms)`);
        } else if (responseTime < 2000) {
          this.targetResponseCategory = 'normal';
          console.log(`Target ${hostname} has normal responsiveness (${responseTime}ms)`);
        } else {
          this.targetResponseCategory = 'slow';
          console.log(`Target ${hostname} is slow (${responseTime}ms)`);
        }
      } catch (error) {
        // HTTP request failed, fall back to 'normal' category
        console.log(`Responsiveness check failed for ${hostname}: ${error.message}`);
        this.targetResponseCategory = 'normal';
      }
      
      return this.targetResponseCategory;
    } catch (error) {
      console.error(`Error checking target responsiveness: ${error.message}`);
      // Default to 'normal' if check fails
      this.targetResponseCategory = 'normal';
      return this.targetResponseCategory;
    }
  }
  
  /**
   * Scan a target with enhanced port detection
   * @param {string} target - URL or hostname to scan
   * @param {Object} options - Scan options
   * @returns {Promise<Object>} - Scan results
   */
  async scan(target, options = {}) {
    try {
      // Record scan start time
      this.scanStartTime = Date.now();
      
      // Normalize target
      const targetInfo = this.normalizeTarget(target);
      
      // Start with a base result object
      const result = {
        target: targetInfo,
        scanTimestamp: new Date().toISOString(),
        scanDurationMs: 0,
        ports: [],
        http: {
          statusCode: null,
          statusMessage: null,
          headers: {},
          server: null,
          contentType: null,
          securityHeaders: this.getDefaultSecurityHeaders()
        },
        nuclei: {
          enabled: this.enableNuclei
        },
        errors: [],
        scan_status: {
          port_scan: {
            success: false,
            error_type: null,
            message: null,
            results_found: false
          },
          http_analysis: {
            success: false,
            error_type: null,
            message: null,
            results_found: false
          },
          vulnerability_scan: {
            success: false,
            error_type: null,
            message: null
          }
        },
        port_detection: {
          url_extraction: {
            ports_found: [],
            extraction_successful: false
          },
          service_mapping: {
            mappings: [],
            mapping_successful: false
          },
          banner_grabbing: {
            banners: {},
            grabbing_successful: false
          }
        }
      };
      
      // Step 1: Perform responsiveness check to adjust timeouts
      await this.checkTargetResponsiveness(targetInfo.hostname);
      
      // Step 2: Enhanced port detection from URL
      if (this.enablePortDetection) {
        try {
          result.port_detection.url_extraction = await this.portDetection.extractPortFromUrl(target);
          
          // Use the extracted ports to enhance the scan
          if (result.port_detection.url_extraction.extraction_successful) {
            // Add extracted ports to the list to scan if they're not already included
            const extractedPorts = result.port_detection.url_extraction.ports_found
              .map(portInfo => portInfo.port.toString());
            
            // Add these ports to the ports to scan
            if (extractedPorts.length > 0) {
              const currentPorts = this.ports.split(',');
              const newPorts = [...new Set([...currentPorts, ...extractedPorts])];
              this.ports = newPorts.join(',');
            }
          }
        } catch (portDetectionError) {
          console.error(`Port detection error: ${portDetectionError.message}`);
          result.errors.push(
            this.errorHandler.formatErrorForOutput(
              this.errorHandler.classifyError(portDetectionError, 'port_detection')
            )
          );
        }
      }
      
      // Step 3: Run port scans with multi-strategy approach
      let portResults = [];
      try {
        // Start with standard scan
        portResults = await this.scanWithMultiStrategy(targetInfo.hostname);
        result.ports = portResults;
        result.scan_status.port_scan = {
          success: true,
          error_type: null,
          message: null,
          results_found: portResults.length > 0
        };
      } catch (portScanError) {
        console.error(`Port scan error: ${portScanError.message}`);
        result.scan_status.port_scan = this.errorHandler.createScanStatus(
          this.errorHandler.classifyError(portScanError, 'port_scan'),
          'port_scan'
        );
        result.errors.push(
          this.errorHandler.formatErrorForOutput(
            this.errorHandler.classifyError(portScanError, 'port_scan')
          )
        );
      }
      
      // Step 4: Service to port mapping if no port results found
      if (portResults.length === 0 && this.enablePortDetection) {
        try {
          // Get services from known protocols
          const protocols = [targetInfo.protocol].filter(p => p); // Filter out empty/null
          
          if (protocols.length > 0) {
            result.port_detection.service_mapping = await this.portDetection.mapServiceToPorts(protocols);
            
            // If service mapping successful, use those ports for an additional scan
            if (result.port_detection.service_mapping.mapping_successful) {
              const mappedPorts = [];
              
              // Extract all ports from mappings
              result.port_detection.service_mapping.mappings.forEach(mapping => {
                mapping.ports.forEach(port => {
                  mappedPorts.push(port.toString());
                });
              });
              
              if (mappedPorts.length > 0) {
                // Try one more port scan with these specific ports
                try {
                  const servicePorts = mappedPorts.join(',');
                  console.log(`Trying service-mapped ports: ${servicePorts}`);
                  
                  const serviceMappedResults = await this.scanPorts(targetInfo.hostname, {
                    ports: servicePorts
                  });
                  
                  // Add any new ports found
                  if (serviceMappedResults && serviceMappedResults.length > 0) {
                    // Merge with existing results, avoiding duplicates
                    const existingPorts = new Set(result.ports.map(p => p.port));
                    
                    serviceMappedResults.forEach(port => {
                      if (!existingPorts.has(port.port)) {
                        result.ports.push(port);
                      }
                    });
                    
                    // Update status if we found ports
                    if (result.ports.length > 0) {
                      result.scan_status.port_scan.results_found = true;
                    }
                  }
                } catch (serviceScanError) {
                  // Don't overwrite main scan errors, just log this one
                  console.error(`Service-mapped port scan error: ${serviceScanError.message}`);
                }
              }
            }
          }
        } catch (mappingError) {
          console.error(`Service mapping error: ${mappingError.message}`);
          // Don't fail the entire scan for this, just log the error
        }
      }
      
      // Step 5: Perform HTTP analysis if appropriate
      try {
        // HTTP analysis
        if (targetInfo.protocol === 'http' || targetInfo.protocol === 'https') {
          const httpUrl = `${targetInfo.protocol}://${targetInfo.hostname}`;
          const httpTimeout = this.calculateAdaptiveTimeout('http', this.timeout);
          
          console.log(`HTTP analysis for ${httpUrl} with adaptive timeout: ${httpTimeout}ms`);
          
          const httpResult = await this.analyzeHttp(httpUrl, httpTimeout);
          result.http = { ...result.http, ...httpResult };
          
          result.scan_status.http_analysis = {
            success: true,
            error_type: null,
            message: null,
            results_found: true
          };
        }
      } catch (httpError) {
        console.error(`HTTP analysis error: ${httpError.message}`);
        result.scan_status.http_analysis = this.errorHandler.createScanStatus(
          this.errorHandler.classifyError(httpError, 'http_analysis'),
          'http_analysis'
        );
        result.errors.push(
          this.errorHandler.formatErrorForOutput(
            this.errorHandler.classifyError(httpError, 'http_analysis')
          )
        );
      }
      
      // Step 6: Perform banner grabbing if enabled
      if (this.enablePortDetection && this.enableBannerGrabbing && result.ports.length > 0) {
        try {
          result.port_detection.banner_grabbing = await this.portDetection.grabBanners(
            targetInfo.hostname, 
            result.ports
          );
          
          // Enhance port information with banners
          if (result.port_detection.banner_grabbing.grabbing_successful) {
            const banners = result.port_detection.banner_grabbing.banners;
            
            // Update port info with banner information
            result.ports = result.ports.map(port => {
              const portNumber = port.port;
              if (banners[portNumber]) {
                return {
                  ...port,
                  banner: banners[portNumber]
                };
              }
              return port;
            });
          }
        } catch (bannerError) {
          console.error(`Banner grabbing error: ${bannerError.message}`);
          // Don't fail the entire scan for banner grabbing issues
        }
      }
      
      // Step 7: Run Nuclei vulnerability scanner if enabled
      if (this.enableNuclei) {
        try {
          const nucleiUrl = `${targetInfo.protocol}://${targetInfo.hostname}`;
          const nucleiTimeout = this.calculateAdaptiveTimeout('nuclei', this.timeout * 4); // Give Nuclei more time
          
          console.log(`Running Nuclei scan on ${nucleiUrl} with timeout: ${nucleiTimeout}ms`);
          
          // FIXED: Make sure to await the complete Nuclei scan process
          const nucleiResults = await this.nucleiScanner.scan(nucleiUrl);
          
          // Check if we need to wait for findings to be saved to the output file
          if (nucleiResults.outputFile && !nucleiResults.findings) {
            console.log('Waiting for Nuclei findings to be processed from output file...');
            
            // Wait for a short time to ensure file processing completes
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            try {
              // Read the output file directly to get the findings
              const outputFile = nucleiResults.outputFile;
              if (fsSync.existsSync(outputFile)) {
                const jsonContent = await fs.promises.readFile(outputFile, 'utf8');
                const findings = JSON.parse(jsonContent);
                
                if (Array.isArray(findings) && findings.length > 0) {
                  console.log(`Found ${findings.length} vulnerability findings in output file`);
                  nucleiResults.findings = findings;
                  nucleiResults.success = true;
                }
              }
            } catch (fileError) {
              console.error(`Error reading Nuclei findings from file: ${fileError.message}`);
            }
          }
          
          result.nuclei = nucleiResults;
          
          result.scan_status.vulnerability_scan = {
            success: nucleiResults.success,
            error_type: nucleiResults.success ? null : 'nuclei_error',
            message: nucleiResults.error || null,
            results_found: Array.isArray(nucleiResults.findings) && nucleiResults.findings.length > 0
          };
          
          if (!nucleiResults.success && nucleiResults.error) {
            result.errors.push({
              component: 'nuclei',
              message: nucleiResults.error,
              type: 'vulnerability_scan',
              timestamp: new Date().toISOString()
            });
          }
        } catch (nucleiError) {
          console.error(`Nuclei scan error: ${nucleiError.message}`);
          result.scan_status.vulnerability_scan = this.errorHandler.createScanStatus(
            this.errorHandler.classifyError(nucleiError, 'vulnerability_scan'),
            'vulnerability_scan'
          );
          result.errors.push(
            this.errorHandler.formatErrorForOutput(
              this.errorHandler.classifyError(nucleiError, 'vulnerability_scan')
            )
          );
        }
      }
      
      // Add enhanced port information
      if (this.enablePortDetection) {
        try {
          const enhancedPorts = this.portDetection.processPortDetectionData(result.port_detection);
          
          // Add enhanced port info if it's not already in results
          if (enhancedPorts.length > 0) {
            const existingPorts = new Set(result.ports.map(p => p.port));
            
            enhancedPorts.forEach(enhancedPort => {
              if (!existingPorts.has(enhancedPort.port)) {
                // This is a new port discovered through advanced methods
                result.ports.push({
                  port: enhancedPort.port,
                  protocol: enhancedPort.protocol || 'tcp',
                  service: enhancedPort.service || '',
                  version: '',
                  state: 'open',
                  banner: enhancedPort.banner || '',
                  detection_method: enhancedPort.detection_method,
                  detection_source: enhancedPort.detection_source
                });
              } else {
                // Enhance existing port with additional information
                const portIndex = result.ports.findIndex(p => p.port === enhancedPort.port);
                if (portIndex >= 0) {
                  // Only add new properties, don't overwrite existing ones
                  for (const [key, value] of Object.entries(enhancedPort)) {
                    if (!result.ports[portIndex][key] && value) {
                      result.ports[portIndex][key] = value;
                    }
                  }
                }
              }
            });
            
            // Update port scan status if we found more ports
            if (result.ports.length > 0) {
              result.scan_status.port_scan.results_found = true;
            }
          }
        } catch (enhancementError) {
          console.error(`Port enhancement error: ${enhancementError.message}`);
          // Don't fail for enhancement errors
        }
      }
      
      // Phase 4, Step 2: Perform alternative detection if traditional scanning yields limited results
      // Only run alternative detection if we have no ports detected or very limited HTTP information
      const shouldRunAlternativeDetection = (
        (result.ports.length === 0) || 
        (result.scan_status.http_analysis.success === false) ||
        (result.scan_status.vulnerability_scan && result.scan_status.vulnerability_scan.success === false)
      );
      
      if (this.enableAlternativeDetection && shouldRunAlternativeDetection) {
        console.log('Traditional scanning yielded limited results, trying alternative detection methods');
        
        try {
          // Initialize alternative detection section if it doesn't exist
          result.alternative_detection = {
            performed: true,
            success: false,
            methods_applied: [],
            technologies_detected: [],
            tls_info: null,
            http_fingerprint: null
          };
          
          // Run alternative detection
          const alternativeResults = await this.performAlternativeDetection(target);
          
          // Update result with alternative detection findings
          result.alternative_detection = alternativeResults;
          
          // If traditional scanning found no ports but alternative detection found technologies,
          // add an HTTP entry to the ports list for better visibility
          if (result.ports.length === 0 && alternativeResults.technologies_detected.length > 0) {
            const protocol = targetInfo.protocol || 'http';
            const port = protocol === 'https' ? 443 : 80;
            
            result.ports.push({
              port: port,
              protocol: 'tcp',
              service: protocol,
              product: protocol,
              version: '',
              state: 'filtered', // Mark as filtered since we couldn't directly detect it
              detection_method: 'alternative',
              technologies: alternativeResults.technologies_detected
                .map(tech => tech.name + (tech.version ? ' ' + tech.version : ''))
                .join(', ')
            });
            
            // Update scan status to reflect that we found something with alternative methods
            result.scan_status.port_scan.results_found = true;
            result.scan_status.port_scan.message = 'Detected through alternative methods';
          }
          
          // If we have SSL/TLS info, enhance the result
          if (alternativeResults.tls_info) {
            result.ssl_info = alternativeResults.tls_info;
          }
          
          // If HTTP fingerprinting was successful, enhance HTTP section
          if (alternativeResults.http_fingerprint) {
            // Enhance HTTP section with additional security headers if not already present
            if (!result.http) {
              result.http = {
                server: alternativeResults.http_fingerprint.headers['server'] || 'unknown',
                contentType: alternativeResults.http_fingerprint.content_type || '',
                statusCode: alternativeResults.http_fingerprint.status || 0,
                statusMessage: alternativeResults.http_fingerprint.status_text || ''
              };
            }
            
            // Enhance security headers if available
            if (!result.http.securityHeaders && alternativeResults.http_fingerprint.headers) {
              const headers = alternativeResults.http_fingerprint.headers;
              result.http.securityHeaders = {
                hasStrictTransportSecurity: headers['strict-transport-security'] !== undefined,
                hasContentSecurityPolicy: headers['content-security-policy'] !== undefined,
                hasXContentTypeOptions: headers['x-content-type-options'] !== undefined,
                hasXFrameOptions: headers['x-frame-options'] !== undefined,
                hasXXSSProtection: headers['x-xss-protection'] !== undefined,
                hasReferrerPolicy: headers['referrer-policy'] !== undefined,
                hasPermissionsPolicy: headers['permissions-policy'] !== undefined,
                strictTransportSecurityValue: headers['strict-transport-security'] || null,
                contentSecurityPolicyValue: headers['content-security-policy'] || null,
                xContentTypeOptionsValue: headers['x-content-type-options'] || null,
                xFrameOptionsValue: headers['x-frame-options'] || null,
                xxssProtectionValue: headers['x-xss-protection'] || null,
                referrerPolicyValue: headers['referrer-policy'] || null,
                permissionsPolicyValue: headers['permissions-policy'] || null
              };
            }
          }
          
          // Add detected security products to the result
          if (alternativeResults.security_products && alternativeResults.security_products.length > 0) {
            result.security_products = alternativeResults.security_products;
          }
          
        } catch (altError) {
          console.error(`Alternative detection failed: ${altError.message}`);
          // Don't fail the entire scan if alternative detection fails
          result.alternative_detection = {
            performed: true,
            success: false,
            error: altError.message
          };
        }
      }
      
      // Calculate total scan duration
      result.scanDurationMs = Date.now() - this.scanStartTime;
      
      // Ensure consistent output format using the formatter
      return this.outputFormatter.formatScanResult(result);
    } catch (error) {
      // Handle any unexpected errors
      console.error(`Unexpected scan error: ${error.message}`);
      
      // Create a minimal result with error information
      const errorResult = {
        target: this.normalizeTarget(target),
        scanTimestamp: new Date().toISOString(),
        scanDurationMs: Date.now() - (this.scanStartTime || Date.now()),
        errors: [
          this.errorHandler.formatErrorForOutput(
            this.errorHandler.classifyError(error, 'scanner')
          )
        ],
        scan_status: {
          port_scan: {
            success: false,
            error_type: 'unexpected_error',
            message: error.message,
            results_found: false
          },
          http_analysis: {
            success: false,
            error_type: 'unexpected_error',
            message: error.message,
            results_found: false
          },
          vulnerability_scan: {
            success: false,
            error_type: 'unexpected_error',
            message: error.message
          }
        }
      };
      
      // Use the output formatter to ensure consistent structure even for errors
      return this.outputFormatter.formatScanResult(errorResult);
    }
  }
  
  /**
   * Scan ports using multi-strategy approach
   * @param {string} target - Target hostname or IP
   * @param {Object} options - Scan options
   * @returns {Promise<Array>} - Array of port objects
   */
  async scanWithMultiStrategy(target, options = {}) {
    try {
      // Try SYN scan first
      console.log(`Performing TCP SYN scan`);
      const synScanResults = await this.scanPorts(target, {
        tcpScanMethod: 'syn',
        ...options
      });
      
      if (synScanResults && synScanResults.length > 0) {
        return synScanResults;
      }
      
      console.log(`Initial TCP scan did not find results, trying fallback strategies...`);
      
      // If SYN scan fails or returns no results, try TCP connect scan
      try {
        console.log(`Trying TCP connect scan...`);
        console.log(`Performing TCP connect scan`);
        const connectScanResults = await this.scanPorts(target, {
          tcpScanMethod: 'connect',
          aggressive: true, // Use more aggressive options for connect scan
          ...options
        });
        
        if (connectScanResults && connectScanResults.length > 0) {
          console.log(`TCP connect scan found ${connectScanResults.length} open ports`);
          return connectScanResults;
        } else {
          console.log(`TCP connect scan did not find any open ports`);
        }
      } catch (connectError) {
        console.log(`TCP connect scan failed: ${connectError.message}`);
      }
      
      // If connect scan fails, try quick scan
      try {
        console.log(`Trying quick scan...`);
        console.log(`Performing TCP SYN scan`);
        const quickScanResults = await this.scanPorts(target, {
          tcpScanMethod: 'syn',
          quick: true,
          ...options
        });
        
        if (quickScanResults && quickScanResults.length > 0) {
          console.log(`Quick scan found ${quickScanResults.length} open ports`);
          return quickScanResults;
        } else {
          console.log(`Quick scan did not find any open ports`);
        }
      } catch (quickError) {
        console.log(`Quick scan failed: ${quickError.message}`);
      }
      
      // If all TCP scan strategies fail, try UDP scan if enabled
      if (this.enableUdpScan) {
        try {
          console.log(`Performing UDP port scan for complementary services...`);
          console.log(`Starting UDP scan on ${target}`);
          const udpScanResults = await this.scanUdpPorts(target, options);
          
          if (udpScanResults && udpScanResults.length > 0) {
            console.log(`UDP scan found ${udpScanResults.length} open ports`);
            return udpScanResults;
          } else {
            console.log(`UDP scan did not find any open ports`);
          }
        } catch (udpError) {
          console.log(`UDP scan failed: ${udpError.message}`);
        }
      } else {
        console.log(`UDP scanning is disabled, skipping`);
      }
      
      // If all strategies fail, return empty array
      return [];
    } catch (error) {
      console.error(`Multi-strategy scan error: ${error.message}`);
      throw error;
    }
  }
  
  /**
   * Scan ports using Nmap
   * @param {string} target - Target hostname or IP
   * @param {Object} options - Scan options
   * @returns {Promise<Array>} - Array of port objects
   */
  scanPorts(target, options = {}) {
    return new Promise((resolve, reject) => {
      try {
        const tcpScanMethod = options.tcpScanMethod || 'syn';
        const isQuickScan = options.quick || false;
        const isAggressive = options.aggressive || this.aggressive;
        const portsToScan = options.ports || this.ports;
        
        // Build Nmap arguments based on scan type
        let nmapArgs = [];
        
        if (tcpScanMethod === 'connect') {
          // TCP connect scan
          nmapArgs.push('-sT');
        } else {
          // Default to SYN scan
          nmapArgs.push('-sS');
        }
        
        // Add version detection for standard and connect scans
        if (tcpScanMethod === 'connect') {
          nmapArgs.push('-sV');
          nmapArgs.push('--version-intensity=7');
        } else if (!isQuickScan) {
          nmapArgs.push('-sV');
        }
        
        // Specify ports
        nmapArgs.push(`-p ${portsToScan}`);
        
        // Add options for quick scan
        if (isQuickScan) {
          nmapArgs.push('-F');
          nmapArgs.push('--min-rate=300');
        } else if (!isAggressive) {
          // Base options for standard scan
          nmapArgs.push('--data-length=24');
        }
        
        // Don't ping the host (assume it's up)
        nmapArgs.push('-Pn');
        
        // Add timeout options based on adaptive calculations
        const adaptiveTimeout = Math.floor(this.calculateAdaptiveTimeout('port', this.portScanTimeout) / 1000);
        nmapArgs.push(`--host-timeout ${adaptiveTimeout}s`);
        nmapArgs.push('--max-retries 2');
        
        // Add timing template based on target response category
        if (this.targetResponseCategory === 'responsive') {
          nmapArgs.push('-T3');
        } else if (this.targetResponseCategory === 'slow') {
          nmapArgs.push('-T2');
        } else {
          nmapArgs.push('-T2');
        }
        
        // Phase 4, Step 1: Apply evasion techniques if enabled
        if (this.enableEvasion) {
          // Determine evasion profile - use more aggressive evasion for slow targets
          let evasionProfile = this.evasionProfile;
          
          if (options.evasionProfile) {
            // Override with options if provided
            evasionProfile = options.evasionProfile;
          } else if (isQuickScan) {
            // Use minimal evasion for quick scans
            evasionProfile = 'minimal';
          } else if (this.targetResponseCategory === 'slow') {
            // Use more aggressive evasion for slow targets
            evasionProfile = 'aggressive';
          }
          
          // Apply evasion techniques based on profile
          nmapArgs = this.evasionTechniques.applyEvasionTechniques(nmapArgs, {
            evasionProfile: evasionProfile,
            isQuickScan: isQuickScan
          });
          
          console.log(`Applied evasion techniques with profile: ${evasionProfile}`);
        } else {
          // If evasion is disabled, just add some basic options
          nmapArgs.push('--randomize-hosts');
        }
        
        // Phase 4, Step 3: Apply proxy configuration to Nmap if enabled
        if (this.enableProxySupport) {
          nmapArgs = this.proxySupport.applyProxyToNmap(nmapArgs, {
            isQuickScan: isQuickScan
          });
          console.log('Applied proxy configuration to Nmap arguments');
        }
        
        // Join all arguments into a string
        const nmapOptions = nmapArgs.join(' ');
        
        console.log(`Starting Nmap scan on ${target} with options: ${nmapOptions}`);
        
        // Calculate scan timeout
        const scanTimeout = this.calculateAdaptiveTimeout('port', this.portScanTimeout);
        console.log(`Using adaptive timeout: ${scanTimeout}ms (${Math.floor(scanTimeout/1000)}s)`);
        
        // Create and configure the scan
        const scan = new nmap.QuickScan(target, nmapOptions);
        
        let timeoutId;
        let scanComplete = false;
        
        // Set up a timeout
        timeoutId = setTimeout(() => {
          if (!scanComplete) {
            console.log(`Nmap scan timeout after ${scanTimeout}ms, cancelling scan...`);
            scan.cancelScan();
            reject(new Error(`Scan cancelled due to timeout after ${scanTimeout}ms`));
          }
        }, scanTimeout);
        
        // Scan events
        scan.on('complete', async (data) => {
          scanComplete = true;
          clearTimeout(timeoutId);
          
          console.log(`Nmap scan completed successfully for ${target}`);
          
          try {
            // Process scan results
            if (!data || data.length === 0 || !data[0].openPorts) {
              // No results found
              resolve([]);
              return;
            }
            
            // Format the results
            const results = data[0].openPorts.map(port => ({
              port: parseInt(port.port, 10),
              protocol: port.protocol || 'tcp',
              service: port.service || '',
              version: port.version || '',
              state: 'open',
              banner: '',
              script_results: {
                service: port.service || ''
              }
            }));
            
            resolve(results);
          } catch (processError) {
            reject(processError);
          }
        });
        
        scan.on('error', (error) => {
          scanComplete = true;
          clearTimeout(timeoutId);
          console.log(`Nmap error: ${error}`);
          reject(new Error(`Nmap scan failed: ${error}`));
        });
        
        // Start the scan
        scan.startScan();
      } catch (error) {
        reject(error);
      }
    });
  }
  
  /**
   * Scan UDP ports using Nmap
   * @param {string} target - Target hostname or IP
   * @param {Object} options - Scan options
   * @returns {Promise<Array>} - Array of port objects
   */
  scanUdpPorts(target, options = {}) {
    return new Promise((resolve, reject) => {
      try {
        const portsToScan = options.udpPorts || this.udpPorts;
        
        console.log(`Performing UDP scan`);
        
        // Build Nmap arguments for UDP scan
        let nmapArgs = [
          '-sU',             // UDP scan
          '-F',              // Fast scan
          '--min-rate=300',  // Min rate to speed up scan
          '-Pn'              // Don't ping the host (assume it's up)
        ];
        
        // Specify ports
        nmapArgs.push(`-p ${portsToScan}`);
        
        // Add timeout options based on adaptive calculations
        const adaptiveTimeout = Math.floor(this.calculateAdaptiveTimeout('port', this.portScanTimeout) / 1000);
        nmapArgs.push(`--host-timeout ${adaptiveTimeout}s`);
        nmapArgs.push('--max-retries 2');
        
        // Add timing template based on target response category
        if (this.targetResponseCategory === 'responsive') {
          nmapArgs.push('-T3');
        } else if (this.targetResponseCategory === 'slow') {
          nmapArgs.push('-T2');
        } else {
          nmapArgs.push('-T2');
        }
        
        // Phase 4, Step 1: Apply evasion techniques for UDP scans if enabled
        if (this.enableEvasion) {
          // For UDP scans, always use minimal evasion profile to avoid excessive slowness
          // UDP scans are naturally slow, so we don't want to make them even slower
          const evasionProfile = 'minimal';
          
          // Apply minimal evasion techniques
          nmapArgs = this.evasionTechniques.applyEvasionTechniques(nmapArgs, {
            evasionProfile: evasionProfile,
            isQuickScan: true // Treat UDP scans as quick scans for evasion
          });
          
          console.log(`Applied minimal evasion techniques for UDP scan`);
        }
        
        // Join all arguments into a string
        const nmapOptions = nmapArgs.join(' ');
        
        console.log(`Starting Nmap scan on ${target} with options: ${nmapOptions}`);
        
        // Calculate scan timeout
        const scanTimeout = this.calculateAdaptiveTimeout('port', this.portScanTimeout);
        console.log(`Using adaptive timeout: ${scanTimeout}ms (${Math.floor(scanTimeout/1000)}s)`);
        
        // Create and configure the scan
        const scan = new nmap.QuickScan(target, nmapOptions);
        
        let timeoutId;
        let scanComplete = false;
        
        // Set up a timeout
        timeoutId = setTimeout(() => {
          if (!scanComplete) {
            scan.cancelScan();
            reject(new Error(`UDP scan cancelled due to timeout after ${scanTimeout}ms`));
          }
        }, scanTimeout);
        
        // Scan events
        scan.on('complete', async (data) => {
          scanComplete = true;
          clearTimeout(timeoutId);
          
          console.log(`Nmap scan completed successfully for ${target}`);
          
          try {
            // Process scan results
            if (!data || data.length === 0 || !data[0].openPorts) {
              // No results found
              resolve([]);
              return;
            }
            
            // Format the results
            const results = data[0].openPorts.map(port => ({
              port: parseInt(port.port, 10),
              protocol: 'udp',
              service: port.service || '',
              version: port.version || '',
              state: 'open',
              banner: ''
            }));
            
            resolve(results);
          } catch (processError) {
            reject(processError);
          }
        });
        
        scan.on('error', (error) => {
          scanComplete = true;
          clearTimeout(timeoutId);
          console.log(`Nmap error: ${error}`);
          reject(new Error(`UDP scan failed: ${error}`));
        });
        
        // Start the scan
        scan.startScan();
      } catch (error) {
        reject(error);
      }
    });
  }
  
  /**
   * Analyze HTTP response headers
   * @param {string} url - URL to analyze
   * @param {number} timeout - Timeout in milliseconds
   * @returns {Promise<Object>} - HTTP analysis results
   */
  async analyzeHttp(url, timeout) {
    try {
      // Make HTTP request with proxy support if enabled
      let response;
      if (this.enableProxySupport) {
        response = await this.proxySupport.makeProxiedRequest(url, {
          maxRetries: 2,
          retryDelay: 1000,
          fallbackToNoProxy: true
        });
      } else {
        response = await axios.get(url, {
          timeout: timeout,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
          },
          validateStatus: () => true, // Don't throw on error status codes
          maxRedirects: 2
        });
      }
      
      // Extract and analyze headers
      const headers = response.headers;
      const contentType = headers['content-type'] || '';
      const server = headers['server'] || '';
      
      // Analyze security headers
      const securityHeaders = {
        hasStrictTransportSecurity: headers['strict-transport-security'] !== undefined,
        hasContentSecurityPolicy: headers['content-security-policy'] !== undefined,
        hasXContentTypeOptions: headers['x-content-type-options'] !== undefined,
        hasXFrameOptions: headers['x-frame-options'] !== undefined,
        hasXXSSProtection: headers['x-xss-protection'] !== undefined,
        hasReferrerPolicy: headers['referrer-policy'] !== undefined,
        hasPermissionsPolicy: headers['permissions-policy'] !== undefined,
        
        strictTransportSecurityValue: headers['strict-transport-security'] || null,
        contentSecurityPolicyValue: headers['content-security-policy'] || null,
        xContentTypeOptionsValue: headers['x-content-type-options'] || null,
        xFrameOptionsValue: headers['x-frame-options'] || null,
        xxssProtectionValue: headers['x-xss-protection'] || null,
        referrerPolicyValue: headers['referrer-policy'] || null,
        permissionsPolicyValue: headers['permissions-policy'] || null
      };
      
      return {
        statusCode: response.status,
        statusMessage: response.statusText,
        headers: headers,
        server: server,
        contentType: contentType,
        securityHeaders: securityHeaders
      };
    } catch (error) {
      console.error(`HTTP analysis error: ${error.message}`);
      throw error;
    }
  }
  
  /**
   * Get default security headers object with all fields initialized to false/null
   * @returns {Object} - Default security headers object
   */
  getDefaultSecurityHeaders() {
    return {
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
    };
  }
  
  /**
   * Perform alternative detection methods when traditional scanning fails
   * @param {string} target - Target URL or hostname
   * @param {Object} options - Detection options
   * @returns {Promise<Object>} - Alternative detection results
   */
  async performAlternativeDetection(target, options = {}) {
    try {
      console.log(`Performing alternative detection methods for ${target}`);
      
      // Check if alternative detection is enabled
      if (!this.enableAlternativeDetection) {
        console.log('Alternative detection is disabled, skipping');
        return {
          success: false,
          reason: 'alternative_detection_disabled',
          methods_applied: []
        };
      }
      
      // Calculate adaptive timeout
      const timeout = this.calculateAdaptiveTimeout('http', this.timeout);
      
      // Run alternative detection with proper timeout
      const detectionResult = await this.alternativeDetection.detect(target, {
        timeout: timeout,
        ...options
      });
      
      console.log(`Alternative detection completed with ${detectionResult.methods_applied.length} methods applied`);
      
      if (detectionResult.technologies_detected.length > 0) {
        console.log(`Detected ${detectionResult.technologies_detected.length} technologies through alternative methods`);
      }
      
      return detectionResult;
    } catch (error) {
      console.error(`Alternative detection error: ${error.message}`);
      return {
        success: false,
        reason: 'alternative_detection_error',
        error: error.message,
        methods_applied: []
      };
    }
  }
  
  /**
   * Normalize a target URL or hostname
   * @param {string} target - Target URL or hostname
   * @returns {Object} - Normalized target information
   */
  normalizeTarget(target) {
    try {
      // Check if the target already has a protocol
      if (!target.includes('://')) {
        // No protocol, assume http
        target = `http://${target}`;
      }
      
      const urlObj = new URL(target);
      
      return {
        original: target,
        hostname: urlObj.hostname,
        protocol: urlObj.protocol.replace(':', '')
      };
    } catch (error) {
      // If URL parsing fails, return best-effort result
      return {
        original: target,
        hostname: target.replace(/^https?:\/\//, '').split('/')[0],
        protocol: target.startsWith('https://') ? 'https' : 'http'
      };
    }
  }
  
  /**
   * Clean up scanner resources including proxy connections
   */
  cleanup() {
    if (this.enableProxySupport && this.proxySupport) {
      this.proxySupport.cleanup();
    }
    console.log('Scanner cleanup completed');
  }
}

module.exports = Scanner;
