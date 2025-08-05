/**
 * BannerGrabber
 * 
 * Module for grabbing service banners from open ports to improve service identification.
 */

const net = require('net');
const tls = require('tls');
const { promisify } = require('util');
const dns = require('dns');
const dnsPromises = dns.promises;

// Timeout for banner grabbing connections (ms)
const DEFAULT_TIMEOUT = 3000;

// Service specific probes to elicit better banner responses
const SERVICE_PROBES = {
  'http': 'GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: */*\r\n\r\n',
  'https': 'GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: */*\r\n\r\n',
  'smtp': 'EHLO netsage.scanner\r\n',
  'pop3': '',  // POP3 servers send banner on connect
  'imap': '',  // IMAP servers send banner on connect
  'ftp': '',   // FTP servers send banner on connect
  'ssh': '',   // SSH servers send banner on connect
  'telnet': '' // Telnet servers send banner on connect
};

class BannerGrabber {
  /**
   * Creates a new BannerGrabber instance
   * @param {Object} options - Options for banner grabbing
   * @param {number} options.timeout - Timeout for connections in milliseconds
   * @param {boolean} options.useTLS - Whether to use TLS for secure services
   */
  constructor(options = {}) {
    this.timeout = options.timeout || DEFAULT_TIMEOUT;
    this.useTLS = options.useTLS !== false;
  }

  /**
   * Grab banners from all specified ports
   * @param {string} host - Target hostname or IP
   * @param {Array} ports - Array of port objects with at least port and protocol properties
   * @returns {Promise<Object>} - Object with port numbers as keys and banner strings as values
   */
  async grabBanners(host, ports) {
    if (!host || !Array.isArray(ports) || ports.length === 0) {
      return {};
    }

    const results = {};
    const promises = [];

    // Process each port in parallel
    for (const portInfo of ports) {
      // Skip ports that aren't open
      if (portInfo.state !== 'open') continue;
      
      const port = portInfo.port;
      const service = portInfo.service || '';
      const protocol = portInfo.protocol || 'tcp';
      
      // Skip UDP ports for banner grabbing (requires different approach)
      if (protocol.toLowerCase() === 'udp') continue;
      
      // Create a promise for each port
      promises.push(
        this.grabBannerFromPort(host, port, service)
          .then(banner => {
            if (banner) {
              results[port] = banner;
            }
          })
          .catch(err => {
            console.error(`Error grabbing banner from ${host}:${port}: ${err.message}`);
            // Don't add to results on error
          })
      );
    }

    // Wait for all banner grabs to complete
    await Promise.allSettled(promises);
    
    return results;
  }

  /**
   * Grab banner from a single port
   * @param {string} host - Target hostname or IP
   * @param {number} port - Port number
   * @param {string} service - Service name if known (for service-specific probing)
   * @returns {Promise<string>} - Banner string or empty string if none received
   */
  async grabBannerFromPort(host, port, service = '') {
    // Determine if we should use TLS based on port and service
    const useSecure = this.shouldUseTLS(port, service);
    
    return new Promise((resolve, reject) => {
      // Setup connection options
      const options = {
        host: host,
        port: port,
        timeout: this.timeout
      };

      // For TLS connections, add options to ignore certificate errors
      if (useSecure) {
        options.rejectUnauthorized = false;
        options.requestCert = true;
      }

      // Create the appropriate socket
      const socket = useSecure
        ? tls.connect(options)
        : net.createConnection(options);

      let banner = '';
      let dataReceived = false;

      // Set encoding for text data
      socket.setEncoding('utf8');

      // Handle connection
      socket.on('connect', () => {
        // Send appropriate probe for the service
        const probe = this.getProbeForService(service, host);
        if (probe) {
          socket.write(probe);
        }
        
        // Set a timeout to close the connection if we've received data
        setTimeout(() => {
          if (dataReceived) {
            socket.end();
          }
        }, this.timeout / 2);
      });

      // Handle data
      socket.on('data', (data) => {
        dataReceived = true;
        banner += data.toString();
        
        // If we have a substantial banner or the banner appears complete, end the connection
        if (banner.length > 200 || this.bannerAppearsComplete(banner, service)) {
          socket.end();
        }
      });

      // Handle connection end
      socket.on('end', () => {
        resolve(this.processBanner(banner, service, port));
      });

      // Handle errors
      socket.on('error', (err) => {
        socket.destroy();
        resolve(''); // Resolve with empty string on error to continue with other ports
      });

      // Handle timeout
      socket.on('timeout', () => {
        socket.end();
        resolve(''); // Resolve with empty string on timeout
      });
    });
  }

  /**
   * Get the appropriate probe for a service
   * @param {string} service - Service name
   * @param {string} host - Target hostname
   * @returns {string} - Probe string or empty string if none defined
   */
  getProbeForService(service, host) {
    if (!service) return '';
    
    const normalizedService = service.toLowerCase().trim();
    const probe = SERVICE_PROBES[normalizedService];
    
    if (!probe) return '';
    
    // Replace template variables
    return probe.replace('${host}', host);
  }

  /**
   * Determine if a banner appears complete based on service-specific patterns
   * @param {string} banner - Banner string received so far
   * @param {string} service - Service name
   * @returns {boolean} - True if banner appears complete
   */
  bannerAppearsComplete(banner, service) {
    if (!banner) return false;
    
    const normalizedService = (service || '').toLowerCase().trim();
    
    // HTTP response is complete when we've received headers and at least some body
    if (normalizedService === 'http' || normalizedService === 'https') {
      return banner.includes('\r\n\r\n') && banner.length > 100;
    }
    
    // FTP banner is complete when we get 220 welcome message
    if (normalizedService === 'ftp') {
      return banner.includes('220 ');
    }
    
    // SSH banner is typically one line
    if (normalizedService === 'ssh') {
      return banner.includes('SSH');
    }
    
    // Default: consider complete when we have at least 50 chars
    return banner.length >= 50;
  }

  /**
   * Process and clean up the banner based on the service
   * @param {string} banner - Raw banner string
   * @param {string} service - Service name
   * @param {number} port - Port number
   * @returns {string} - Processed banner
   */
  processBanner(banner, service, port) {
    if (!banner) return '';
    
    // Limit banner length and clean up
    let processed = banner
      .replace(/[\x00-\x09\x0B-\x0C\x0E-\x1F\x7F]/g, '') // Remove non-printable chars except newlines
      .trim()
      .slice(0, 500); // Limit length
    
    const normalizedService = (service || '').toLowerCase().trim();
    
    // Additional service-specific processing
    if (normalizedService === 'http' || normalizedService === 'https') {
      // Extract HTTP headers only
      const headerEnd = processed.indexOf('\r\n\r\n');
      if (headerEnd > 0) {
        processed = processed.substring(0, headerEnd);
      }
    }
    
    return processed;
  }

  /**
   * Determine if we should use TLS for a connection based on port and service
   * @param {number} port - Port number
   * @param {string} service - Service name
   * @returns {boolean} - True if TLS should be used
   */
  shouldUseTLS(port, service) {
    if (!this.useTLS) return false;
    
    // Common secure ports
    const securePorts = [443, 465, 636, 993, 995, 8443];
    
    // Check if port is commonly secure
    if (securePorts.includes(port)) return true;
    
    // Check service name for secure indicators
    const normalizedService = (service || '').toLowerCase().trim();
    return (
      normalizedService === 'https' ||
      normalizedService === 'ftps' ||
      normalizedService === 'smtps' ||
      normalizedService === 'imaps' ||
      normalizedService === 'pop3s' ||
      normalizedService === 'ldaps' ||
      normalizedService.includes('ssl') ||
      normalizedService.includes('tls')
    );
  }
}

module.exports = BannerGrabber;
