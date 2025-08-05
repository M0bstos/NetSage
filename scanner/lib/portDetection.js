/**
 * PortDetection
 * 
 * Enhanced port detection module for extracting and inferring port information
 * from URLs, service names, and other sources.
 */

const { URL } = require('url');
const { promisify } = require('util');
const dns = require('dns');
const ServiceMappings = require('./utils/serviceMappings');
const BannerGrabber = require('./utils/bannerGrabber');

// Default ports to check when not specified
const DEFAULT_PORTS = [
  // Web services
  { port: 80, protocol: 'tcp', description: 'HTTP' },
  { port: 443, protocol: 'tcp', description: 'HTTPS' },
  { port: 8080, protocol: 'tcp', description: 'HTTP alternate' },
  { port: 8443, protocol: 'tcp', description: 'HTTPS alternate' },
  
  // FTP
  { port: 21, protocol: 'tcp', description: 'FTP' },
  
  // SSH
  { port: 22, protocol: 'tcp', description: 'SSH' },
  
  // Mail services
  { port: 25, protocol: 'tcp', description: 'SMTP' },
  { port: 110, protocol: 'tcp', description: 'POP3' },
  { port: 143, protocol: 'tcp', description: 'IMAP' },
  
  // Database services
  { port: 3306, protocol: 'tcp', description: 'MySQL' },
  { port: 5432, protocol: 'tcp', description: 'PostgreSQL' },
  { port: 27017, protocol: 'tcp', description: 'MongoDB' },
  
  // Common UDP services
  { port: 53, protocol: 'udp', description: 'DNS' },
  { port: 123, protocol: 'udp', description: 'NTP' },
  { port: 161, protocol: 'udp', description: 'SNMP' }
];

class PortDetection {
  /**
   * Creates a new PortDetection instance
   * @param {Object} options - Options for port detection
   * @param {number} options.timeout - Timeout for operations in milliseconds
   * @param {boolean} options.enableBannerGrabbing - Whether to enable banner grabbing
   */
  constructor(options = {}) {
    this.timeout = options.timeout || 5000;
    this.enableBannerGrabbing = options.enableBannerGrabbing !== false;
    this.serviceMappings = new ServiceMappings();
    
    // Create banner grabber only if enabled
    if (this.enableBannerGrabbing) {
      this.bannerGrabber = new BannerGrabber({
        timeout: this.timeout,
        useTLS: true
      });
    }
  }
  
  /**
   * Extract port information from a URL
   * @param {string} target - Target URL or hostname
   * @returns {Promise<Object>} - Extracted port information
   */
  async extractPortFromUrl(target) {
    try {
      const result = {
        ports_found: [],
        extraction_successful: false,
        message: null
      };
      
      // Handle cases where target is not a URL (just hostname)
      let url;
      try {
        // Try to parse as URL
        if (!target.includes('://')) {
          // Add http:// if no protocol is specified
          target = `http://${target}`;
        }
        
        url = new URL(target);
      } catch (parseError) {
        // Not a valid URL, try to extract host and port directly
        const parts = target.split(':');
        if (parts.length === 2) {
          const port = parseInt(parts[1], 10);
          if (!isNaN(port)) {
            result.ports_found.push({
              port: port,
              protocol: 'tcp',
              detected_from: 'hostname:port format',
              hostname: parts[0]
            });
            
            result.extraction_successful = true;
            return result;
          }
        }
        
        // No valid port found in non-URL format
        result.message = `Not a valid URL: ${parseError.message}`;
        return result;
      }
      
      // Successfully parsed URL
      let detectedPort;
      
      // Check if port is explicitly specified in URL
      if (url.port) {
        detectedPort = parseInt(url.port, 10);
      } else {
        // No explicit port, use default for protocol
        detectedPort = this.serviceMappings.getDefaultPortForProtocol(url.protocol.replace(':', ''));
      }
      
      if (detectedPort) {
        result.ports_found.push({
          port: detectedPort,
          protocol: 'tcp',
          detected_from: url.port ? 'explicit_url_port' : 'protocol_default',
          hostname: url.hostname,
          protocol_name: url.protocol.replace(':', '')
        });
        
        result.extraction_successful = true;
      }
      
      return result;
    } catch (error) {
      console.error(`Error extracting port from URL: ${error.message}`);
      return {
        ports_found: [],
        extraction_successful: false,
        message: `Error extracting port: ${error.message}`
      };
    }
  }
  
  /**
   * Map services to their standard ports
   * @param {Array} services - Array of service names
   * @returns {Promise<Object>} - Service to port mappings
   */
  async mapServiceToPorts(services) {
    try {
      const result = {
        mappings: [],
        mapping_successful: false,
        message: null
      };
      
      if (!Array.isArray(services) || services.length === 0) {
        result.message = 'No services provided for mapping';
        return result;
      }
      
      let mappingsFound = false;
      
      // Process each service
      for (const service of services) {
        if (!service) continue;
        
        // Get ports for this service
        const ports = this.serviceMappings.getPortsForService(service);
        
        if (ports && ports.length > 0) {
          result.mappings.push({
            service: service,
            ports: ports,
            protocol: this.serviceMappings.getServiceInfo(service)?.protocol || 'tcp'
          });
          
          mappingsFound = true;
        }
      }
      
      result.mapping_successful = mappingsFound;
      
      if (!mappingsFound) {
        result.message = 'No port mappings found for the provided services';
      }
      
      return result;
    } catch (error) {
      console.error(`Error mapping services to ports: ${error.message}`);
      return {
        mappings: [],
        mapping_successful: false,
        message: `Error mapping services: ${error.message}`
      };
    }
  }
  
  /**
   * Check common ports for standard services
   * @param {string} target - Target hostname or IP
   * @returns {Promise<Object>} - Port check results
   */
  async checkCommonPorts(target) {
    try {
      // This would typically involve connecting to common ports
      // to check for responses, but that's already handled by the
      // Scanner class's port scanning. Here we just return the list
      // of common ports that should be checked.
      
      return {
        common_ports: DEFAULT_PORTS,
        message: 'Common ports that should be checked'
      };
    } catch (error) {
      console.error(`Error checking common ports: ${error.message}`);
      return {
        common_ports: [],
        message: `Error checking common ports: ${error.message}`
      };
    }
  }
  
  /**
   * Perform banner grabbing on detected ports
   * @param {string} host - Target hostname or IP
   * @param {Array} ports - Array of port objects with at least port and protocol properties
   * @returns {Promise<Object>} - Banner grabbing results
   */
  async grabBanners(host, ports) {
    try {
      const result = {
        banners: {},
        grabbing_successful: false,
        message: null
      };
      
      // Skip if banner grabbing is disabled
      if (!this.enableBannerGrabbing) {
        result.message = 'Banner grabbing is disabled';
        return result;
      }
      
      if (!host) {
        result.message = 'No host provided for banner grabbing';
        return result;
      }
      
      if (!Array.isArray(ports) || ports.length === 0) {
        result.message = 'No ports provided for banner grabbing';
        return result;
      }
      
      // Perform banner grabbing
      result.banners = await this.bannerGrabber.grabBanners(host, ports);
      result.grabbing_successful = Object.keys(result.banners).length > 0;
      
      if (!result.grabbing_successful) {
        result.message = 'No banners were successfully grabbed';
      }
      
      return result;
    } catch (error) {
      console.error(`Error grabbing banners: ${error.message}`);
      return {
        banners: {},
        grabbing_successful: false,
        message: `Error grabbing banners: ${error.message}`
      };
    }
  }
  
  /**
   * Process port detection data and generate enhanced port information
   * @param {Object} portDetectionData - Data from various port detection methods
   * @returns {Array} - Enhanced port information
   */
  processPortDetectionData(portDetectionData) {
    const enhancedPorts = [];
    
    // Process URL extraction ports
    if (portDetectionData.url_extraction && 
        Array.isArray(portDetectionData.url_extraction.ports_found)) {
      for (const port of portDetectionData.url_extraction.ports_found) {
        enhancedPorts.push({
          port: port.port,
          protocol: port.protocol || 'tcp',
          detection_method: 'url_extraction',
          detection_source: port.detected_from || 'url',
          description: `Detected from URL ${port.protocol_name || 'unknown protocol'}`
        });
      }
    }
    
    // Process service mapping ports
    if (portDetectionData.service_mapping && 
        Array.isArray(portDetectionData.service_mapping.mappings)) {
      for (const mapping of portDetectionData.service_mapping.mappings) {
        for (const port of mapping.ports) {
          enhancedPorts.push({
            port: port,
            protocol: mapping.protocol || 'tcp',
            service: mapping.service,
            detection_method: 'service_mapping',
            detection_source: 'service_name',
            description: `Mapped from service: ${mapping.service}`
          });
        }
      }
    }
    
    // Process banner information
    if (portDetectionData.banner_grabbing && 
        portDetectionData.banner_grabbing.banners) {
      const banners = portDetectionData.banner_grabbing.banners;
      
      for (const port in banners) {
        // Find if port already exists in enhancedPorts
        const portNum = parseInt(port, 10);
        const existingIndex = enhancedPorts.findIndex(p => p.port === portNum);
        
        if (existingIndex >= 0) {
          // Update existing port with banner
          enhancedPorts[existingIndex].banner = banners[port];
          enhancedPorts[existingIndex].banner_grabbed = true;
        } else {
          // Add new port
          enhancedPorts.push({
            port: portNum,
            protocol: 'tcp',
            banner: banners[port],
            detection_method: 'banner_grabbing',
            banner_grabbed: true,
            description: `Port with banner response`
          });
        }
      }
    }
    
    return enhancedPorts;
  }
}

module.exports = PortDetection;
