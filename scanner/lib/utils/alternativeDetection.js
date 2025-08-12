/**
 * Alternative Detection Methods Module
 * 
 * This module provides alternative methods for service and technology detection
 * when traditional port scanning methods fail or are blocked.
 * 
 * Phase 4, Step 2 Implementation:
 * - Passive service detection
 * - TLS/SSL certificate analysis
 * - HTTP response fingerprinting
 * - JavaScript/CSS fingerprinting for technology detection
 */

const https = require('https');
const { URL } = require('url');
const axios = require('axios');
const crypto = require('crypto');
const cheerio = require('cheerio');
const tls = require('tls');

class AlternativeDetection {
  /**
   * Create a new AlternativeDetection instance
   * @param {Object} options - Options for alternative detection
   * @param {number} options.timeout - Timeout for detection operations in milliseconds
   * @param {boolean} options.enableSSL - Enable SSL certificate analysis
   * @param {boolean} options.enableHTTP - Enable HTTP response fingerprinting
   * @param {boolean} options.enableJS - Enable JavaScript/CSS fingerprinting
   */
  constructor(options = {}) {
    this.timeout = options.timeout || 10000; // Default 10 seconds
    this.enableSSL = options.enableSSL !== false;
    this.enableHTTP = options.enableHTTP !== false;
    this.enableJS = options.enableJS !== false;
    
    // User-agent for requests
    this.userAgent = options.userAgent || 
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36';
    
    // Technology fingerprints
    this.technologyFingerprints = {
      javascript: {
        jquery: [/jquery[.-](\d+\.\d+\.\d+)/i, /\/jquery\.min\.js/i],
        react: [/react(-dom)?(@|-)(\d+\.\d+\.\d+)/i, /\bReact\b/],
        angular: [/angular[.-](\d+\.\d+\.\d+)/i, /ng-app/],
        vue: [/vue(@|-)(\d+\.\d+\.\d+)/i, /v-bind/],
        bootstrap: [/bootstrap[.-](\d+\.\d+\.\d+)/i, /class=["']btn/],
        wordpress: [/wp-content/i, /wp-includes/i],
        drupal: [/drupal\.js/i, /Drupal\.settings/],
      },
      headers: {
        nginx: /nginx\/(\d+\.\d+\.\d+)/i,
        apache: /apache\/(\d+\.\d+\.\d+)/i,
        iis: /microsoft-iis\/(\d+\.\d+)/i,
        php: /php\/(\d+\.\d+\.\d+)/i,
        nodejs: /node\/v(\d+\.\d+\.\d+)/i,
        aspnet: /ASP\.NET/i,
        cloudflare: /cloudflare/i,
        aws: /AmazonS3|CloudFront|AWSELB/i,
      },
      cookies: {
        php: /_php/i,
        aspnet: /_asp/i,
        jsessionid: /JSESSIONID/i,
        django: /django/i,
        wordpress: /wordpress_|wp-/i,
      },
      security: {
        waf: {
          cloudflare: /cloudflare/i,
          sucuri: /sucuri/i,
          incapsula: /incapsula/i,
          akamai: /akamai/i,
          fortinet: /fortinet/i,
          f5: /F5/i,
        },
      }
    };
  }

  /**
   * Perform alternative detection methods on a target
   * @param {string} target - Target URL or hostname
   * @param {Object} options - Detection options
   * @returns {Promise<Object>} - Detection results
   */
  async detect(target, options = {}) {
    // Normalize target to ensure it has a protocol
    const normalizedTarget = this.normalizeTarget(target);
    
    // Initialize results object
    const results = {
      target: normalizedTarget,
      timestamp: new Date().toISOString(),
      success: false,
      methods_applied: [],
      technologies_detected: [],
      tls_info: null,
      http_fingerprint: null,
      frontend_technologies: [],
      security_products: [],
      detection_source: 'alternative',
      errors: []
    };
    
    try {
      // SSL/TLS certificate analysis
      if (this.enableSSL && normalizedTarget.protocol === 'https:') {
        try {
          console.log(`Performing TLS/SSL certificate analysis for ${normalizedTarget.href}`);
          const sslInfo = await this.analyzeTLSCertificate(normalizedTarget.hostname, options.port || 443);
          results.tls_info = sslInfo;
          results.methods_applied.push('ssl_certificate');
          
          // Add SSL/TLS specific technologies
          if (sslInfo.issuer) {
            if (sslInfo.issuer.includes('Let\'s Encrypt')) {
              results.technologies_detected.push({
                name: 'Let\'s Encrypt',
                category: 'certificate',
                confidence: 'high'
              });
            } else if (sslInfo.issuer.includes('DigiCert')) {
              results.technologies_detected.push({
                name: 'DigiCert',
                category: 'certificate',
                confidence: 'high'
              });
            }
          }
        } catch (sslError) {
          console.error(`SSL analysis error: ${sslError.message}`);
          results.errors.push({
            method: 'ssl_certificate',
            error: sslError.message
          });
        }
      }
      
      // HTTP response fingerprinting
      if (this.enableHTTP) {
        try {
          console.log(`Performing HTTP response fingerprinting for ${normalizedTarget.href}`);
          const httpInfo = await this.analyzeHTTPResponse(normalizedTarget.href);
          results.http_fingerprint = httpInfo;
          results.methods_applied.push('http_fingerprint');
          
          // Process HTTP fingerprints
          if (httpInfo.headers) {
            // Server header detection
            const serverHeader = httpInfo.headers['server'];
            if (serverHeader) {
              results.technologies_detected.push({
                name: serverHeader,
                category: 'server',
                confidence: 'high',
                version: this.extractVersion(serverHeader)
              });
            }
            
            // Check for WAF signatures in headers
            for (const [wafName, pattern] of Object.entries(this.technologyFingerprints.security.waf)) {
              for (const [header, value] of Object.entries(httpInfo.headers)) {
                if (pattern.test(value)) {
                  results.security_products.push({
                    name: wafName,
                    type: 'waf',
                    confidence: 'high'
                  });
                  break;
                }
              }
            }
            
            // Check for technology headers
            for (const [tech, pattern] of Object.entries(this.technologyFingerprints.headers)) {
              for (const [header, value] of Object.entries(httpInfo.headers)) {
                if (pattern.test(value)) {
                  results.technologies_detected.push({
                    name: tech,
                    category: 'server',
                    confidence: 'high',
                    version: this.extractVersion(value, pattern)
                  });
                  break;
                }
              }
            }
            
            // Check for technology cookies
            if (httpInfo.cookies) {
              for (const [tech, pattern] of Object.entries(this.technologyFingerprints.cookies)) {
                for (const cookie of httpInfo.cookies) {
                  if (pattern.test(cookie)) {
                    results.technologies_detected.push({
                      name: tech,
                      category: 'application',
                      confidence: 'medium'
                    });
                    break;
                  }
                }
              }
            }
          }
        } catch (httpError) {
          console.error(`HTTP fingerprinting error: ${httpError.message}`);
          results.errors.push({
            method: 'http_fingerprint',
            error: httpError.message
          });
        }
      }
      
      // JavaScript/CSS fingerprinting for technology detection
      if (this.enableJS && results.http_fingerprint && results.http_fingerprint.body) {
        try {
          console.log(`Performing JavaScript/CSS fingerprinting for ${normalizedTarget.href}`);
          const jsInfo = await this.analyzeJSCSSTechnologies(normalizedTarget.href, results.http_fingerprint.body);
          results.frontend_technologies = jsInfo;
          results.methods_applied.push('js_css_fingerprint');
          
          // Add detected frontend technologies to the main results
          for (const tech of jsInfo) {
            results.technologies_detected.push({
              ...tech,
              category: 'frontend'
            });
          }
        } catch (jsError) {
          console.error(`JS/CSS fingerprinting error: ${jsError.message}`);
          results.errors.push({
            method: 'js_css_fingerprint',
            error: jsError.message
          });
        }
      }
      
      // Mark success if any methods were applied
      if (results.methods_applied.length > 0) {
        results.success = true;
      }
      
      return results;
    } catch (error) {
      console.error(`Alternative detection error: ${error.message}`);
      results.errors.push({
        method: 'general',
        error: error.message
      });
      return results;
    }
  }
  
  /**
   * Analyze TLS/SSL certificate
   * @param {string} hostname - Target hostname
   * @param {number} port - Target port
   * @returns {Promise<Object>} - Certificate information
   */
  async analyzeTLSCertificate(hostname, port = 443) {
    return new Promise((resolve, reject) => {
      try {
        const options = {
          host: hostname,
          port: port,
          rejectUnauthorized: false, // Allow self-signed certificates
          timeout: this.timeout
        };
        
        // Connect to the server and retrieve certificate info
        const socket = tls.connect(options, () => {
          try {
            // Get certificate
            const cert = socket.getPeerCertificate();
            
            // Close socket
            socket.end();
            
            if (Object.keys(cert).length === 0) {
              return reject(new Error('No certificate found'));
            }
            
            // Format certificate information
            const certInfo = {
              subject: cert.subject ? 
                `${cert.subject.CN || ''}${cert.subject.O ? ', ' + cert.subject.O : ''}` : 'Unknown',
              issuer: cert.issuer ?
                `${cert.issuer.CN || ''}${cert.issuer.O ? ', ' + cert.issuer.O : ''}` : 'Unknown',
              valid_from: cert.valid_from,
              valid_to: cert.valid_to,
              fingerprint: cert.fingerprint,
              serial_number: cert.serialNumber,
              version: cert.version,
              alt_names: cert.subjectaltname ? 
                cert.subjectaltname.split(', ').map(name => name.replace('DNS:', '')) : [],
              signature_algorithm: cert.signatureAlgorithm,
              is_self_signed: cert.issuer && cert.subject &&
                cert.issuer.CN === cert.subject.CN &&
                cert.issuer.O === cert.subject.O,
            };
            
            resolve(certInfo);
          } catch (certError) {
            socket.end();
            reject(certError);
          }
        });
        
        // Handle errors
        socket.on('error', (error) => {
          reject(error);
        });
        
        // Handle timeout
        socket.setTimeout(this.timeout, () => {
          socket.end();
          reject(new Error(`TLS connection timed out after ${this.timeout}ms`));
        });
      } catch (error) {
        reject(error);
      }
    });
  }
  
  /**
   * Analyze HTTP response for fingerprinting
   * @param {string} url - Target URL
   * @returns {Promise<Object>} - HTTP fingerprint information
   */
  async analyzeHTTPResponse(url) {
    try {
      // Make HTTP request
      const response = await axios.get(url, {
        timeout: this.timeout,
        maxRedirects: 2,
        validateStatus: () => true, // Accept any status code
        headers: {
          'User-Agent': this.userAgent,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'gzip, deflate',
          'Connection': 'close',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache'
        }
      });
      
      // Extract cookies from headers
      let cookies = [];
      if (response.headers['set-cookie']) {
        if (Array.isArray(response.headers['set-cookie'])) {
          cookies = response.headers['set-cookie'].map(cookie => cookie.split(';')[0]);
        } else {
          cookies = [response.headers['set-cookie'].split(';')[0]];
        }
      }
      
      // Calculate response hash for unique identification
      const contentHash = crypto
        .createHash('sha256')
        .update(response.data.toString())
        .digest('hex');
      
      // Extract HTTP response details
      return {
        status: response.status,
        status_text: response.statusText,
        headers: response.headers,
        content_type: response.headers['content-type'] || '',
        content_length: parseInt(response.headers['content-length'] || '0'),
        cookies: cookies,
        body: response.data,
        hash: contentHash,
        redirect_count: response.request._redirectable._redirectCount || 0,
      };
    } catch (error) {
      throw new Error(`HTTP analysis error: ${error.message}`);
    }
  }
  
  /**
   * Analyze JavaScript and CSS for technology fingerprinting
   * @param {string} url - Target URL
   * @param {string} html - HTML content
   * @returns {Promise<Array>} - Detected technologies
   */
  async analyzeJSCSSTechnologies(url, html) {
    try {
      // Load HTML with cheerio
      const $ = cheerio.load(html);
      const technologies = [];
      
      // Extract JavaScript file references
      const jsFiles = [];
      $('script[src]').each((i, el) => {
        const src = $(el).attr('src');
        if (src) {
          jsFiles.push(src);
        }
      });
      
      // Extract CSS file references
      const cssFiles = [];
      $('link[rel="stylesheet"]').each((i, el) => {
        const href = $(el).attr('href');
        if (href) {
          cssFiles.push(href);
        }
      });
      
      // Check inline scripts
      let inlineScripts = '';
      $('script:not([src])').each((i, el) => {
        inlineScripts += $(el).html() + '\n';
      });
      
      // Check for JS framework fingerprints
      for (const [tech, patterns] of Object.entries(this.technologyFingerprints.javascript)) {
        // Check script sources
        for (const jsFile of jsFiles) {
          for (const pattern of patterns) {
            if (pattern.test(jsFile)) {
              technologies.push({
                name: this.capitalizeFirstLetter(tech),
                confidence: 'high',
                version: this.extractVersion(jsFile, pattern),
                source: 'js_src'
              });
              break;
            }
          }
        }
        
        // Check inline scripts
        for (const pattern of patterns) {
          if (pattern.test(inlineScripts)) {
            // Only add if not already detected from script src
            if (!technologies.some(t => t.name.toLowerCase() === tech)) {
              technologies.push({
                name: this.capitalizeFirstLetter(tech),
                confidence: 'medium',
                version: this.extractVersion(inlineScripts, pattern),
                source: 'inline_js'
              });
            }
            break;
          }
        }
        
        // Check HTML for framework-specific attributes or patterns
        const htmlContent = $.html();
        for (const pattern of patterns) {
          if (pattern.test(htmlContent)) {
            // Only add if not already detected from other sources
            if (!technologies.some(t => t.name.toLowerCase() === tech)) {
              technologies.push({
                name: this.capitalizeFirstLetter(tech),
                confidence: 'medium',
                version: null,
                source: 'html'
              });
            }
            break;
          }
        }
      }
      
      // Check for CMS specific patterns
      const htmlContent = $.html();
      if (htmlContent) {
        // WordPress specific checks
        if (
          /wp-content|wp-includes|wp-json/i.test(htmlContent) ||
          $('meta[name="generator"][content*="WordPress"]').length
        ) {
          technologies.push({
            name: 'WordPress',
            confidence: 'high',
            version: this.extractWordPressVersion(htmlContent),
            source: 'cms_fingerprint'
          });
        }
        
        // Drupal specific checks
        if (
          /Drupal\.settings|drupal-core/i.test(htmlContent) ||
          $('meta[name="generator"][content*="Drupal"]').length
        ) {
          technologies.push({
            name: 'Drupal',
            confidence: 'high',
            version: null,
            source: 'cms_fingerprint'
          });
        }
        
        // Joomla specific checks
        if (
          /joomla!/i.test(htmlContent) ||
          $('meta[name="generator"][content*="Joomla"]').length
        ) {
          technologies.push({
            name: 'Joomla',
            confidence: 'high',
            version: null,
            source: 'cms_fingerprint'
          });
        }
      }
      
      return technologies;
    } catch (error) {
      throw new Error(`JS/CSS analysis error: ${error.message}`);
    }
  }
  
  /**
   * Extract version from a string using a pattern
   * @param {string} text - Text to extract version from
   * @param {RegExp} pattern - Optional regex pattern with capturing group
   * @returns {string|null} - Extracted version or null
   */
  extractVersion(text, pattern = null) {
    if (!text || typeof text !== 'string') return null;
    
    if (pattern) {
      const match = text.match(pattern);
      if (match && match[1]) {
        return match[1];
      }
    }
    
    // Default version regex patterns
    const versionPatterns = [
      /(\d+\.\d+\.\d+)/,           // matches 1.2.3
      /v(\d+\.\d+\.\d+)/,          // matches v1.2.3
      /version[\/\\s:=_-](\d+\.\d+(\.\d+)?)/i, // matches version 1.2 or version 1.2.3
      /(\d+\.\d+(\.\d+)?)/         // fallback: matches any 1.2 or 1.2.3
    ];
    
    for (const vPattern of versionPatterns) {
      try {
        const match = String(text).match(vPattern);
        if (match && match[1]) {
          return match[1];
        }
      } catch (error) {
        // Skip this pattern if it fails
        continue;
      }
    }
    
    return null;
  }
  
  /**
   * Extract WordPress version from HTML
   * @param {string} html - HTML content
   * @returns {string|null} - WordPress version or null
   */
  extractWordPressVersion(html) {
    // Common patterns for WordPress version
    const wpVersionPatterns = [
      /<meta name="generator" content="WordPress (\d+\.\d+(\.\d+)?)"/i,
      /wp-includes\/js\/wp-emoji-release\.min\.js\?ver=(\d+\.\d+(\.\d+)?)/i,
      /wp-content\/themes\/[^\/]+\/style\.css\?ver=(\d+\.\d+(\.\d+)?)/i
    ];
    
    for (const pattern of wpVersionPatterns) {
      const match = html.match(pattern);
      if (match && match[1]) {
        return match[1];
      }
    }
    
    return null;
  }
  
  /**
   * Normalize target URL
   * @param {string} target - URL or hostname
   * @returns {URL} - Normalized URL object
   */
  normalizeTarget(target) {
    // Check if target already has a protocol
    if (!target.includes('://')) {
      // Add https:// as default protocol
      target = `https://${target}`;
    }
    
    return new URL(target);
  }
  
  /**
   * Capitalize first letter of a string
   * @param {string} string - Input string
   * @returns {string} - String with first letter capitalized
   */
  capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
  }
}

module.exports = AlternativeDetection;
