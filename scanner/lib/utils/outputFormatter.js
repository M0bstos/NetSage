/**
 * OutputFormatter
 * 
 * Ensures that all scan results conform to a consistent output format
 * regardless of which scan components succeed or fail.
 */

class OutputFormatter {
  /**
   * Format the scan result to ensure uniformity
   * @param {Object} scanData - The scan data to format
   * @returns {Object} - Formatted scan data with all required fields
   */
  formatScanResult(scanData) {
    // Start with a template containing all required fields with defaults
    const template = this.getOutputTemplate();
    
    // Merge scan data with template
    const result = this.mergeWithTemplate(scanData, template);
    
    // Ensure all required sections exist
    this.ensureRequiredSections(result);
    
    // Validate the structure
    this.validateStructure(result);
    
    return result;
  }
  
  /**
   * Get the complete output template with all required fields and default values
   * @returns {Object} - Template object with default values
   */
  getOutputTemplate() {
    return {
      target: {
        original: "",
        hostname: "",
        protocol: "http"
      },
      scanTimestamp: new Date().toISOString(),
      scanDurationMs: 0,
      ports: [],
      http: {
        statusCode: null,
        statusMessage: null,
        headers: {},
        server: null,
        contentType: null,
        securityHeaders: {
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
      nuclei: {
        enabled: false,
        findings: []
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
          message: null,
          results_found: false
        }
      },
      // New section for enhanced port detection (always present)
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
  }
  
  /**
   * Merge the scan data with the template
   * @param {Object} scanData - The scan data
   * @param {Object} template - The template object
   * @returns {Object} - Merged object
   */
  mergeWithTemplate(scanData, template) {
    // Deep copy the template
    const result = JSON.parse(JSON.stringify(template));
    
    // Recursively merge scanData into result
    this.deepMerge(result, scanData);
    
    return result;
  }
  
  /**
   * Deep merge two objects
   * @param {Object} target - Target object
   * @param {Object} source - Source object
   * @returns {Object} - Merged object
   */
  deepMerge(target, source) {
    if (!source) return target;
    
    Object.keys(source).forEach(key => {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        if (!target[key]) target[key] = {};
        this.deepMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    });
    
    return target;
  }
  
  /**
   * Ensure all required sections exist in the result
   * @param {Object} result - The result object to validate
   */
  ensureRequiredSections(result) {
    // List of required top-level sections
    const requiredSections = [
      'target', 'scanTimestamp', 'ports', 'http', 'nuclei', 
      'errors', 'scan_status', 'port_detection'
    ];
    
    // Ensure each section exists
    requiredSections.forEach(section => {
      if (!result[section]) {
        // Use default from template if section is missing
        const template = this.getOutputTemplate();
        result[section] = template[section];
      }
    });
  }
  
  /**
   * Validate the structure of the result
   * @param {Object} result - The result object to validate
   */
  validateStructure(result) {
    // Ensure ports is an array
    if (!Array.isArray(result.ports)) {
      result.ports = [];
    }
    
    // Ensure each port has all required fields
    result.ports = result.ports.map(port => {
      return {
        port: port.port || 0,
        protocol: port.protocol || "tcp",
        service: port.service || "",
        version: port.version || "",
        state: port.state || "unknown",
        banner: port.banner || "",
        script_results: port.script_results || {}
      };
    });
    
    // Ensure errors is an array
    if (!Array.isArray(result.errors)) {
      result.errors = [];
    }
    
    // Validate port_detection section
    if (!result.port_detection) {
      result.port_detection = this.getOutputTemplate().port_detection;
    }
    
    // Ensure port_detection.url_extraction.ports_found is an array
    if (!Array.isArray(result.port_detection.url_extraction.ports_found)) {
      result.port_detection.url_extraction.ports_found = [];
    }
    
    // Ensure port_detection.service_mapping.mappings is an array
    if (!Array.isArray(result.port_detection.service_mapping.mappings)) {
      result.port_detection.service_mapping.mappings = [];
    }
    
    // Ensure port_detection.banner_grabbing.banners is an object
    if (typeof result.port_detection.banner_grabbing.banners !== 'object' || 
        result.port_detection.banner_grabbing.banners === null) {
      result.port_detection.banner_grabbing.banners = {};
    }
    
    return result;
  }
}

module.exports = OutputFormatter;
