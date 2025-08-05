/**
 * ErrorHandler
 * 
 * Centralizes error handling for the scanner to ensure consistent error reporting.
 */

// Error types for classification
const ERROR_TYPES = {
  TIMEOUT: 'timeout',
  CONNECTION_REFUSED: 'connection_refused',
  HOST_UNREACHABLE: 'host_unreachable',
  DNS_RESOLUTION: 'dns_resolution',
  FIREWALL_BLOCK: 'firewall_block',
  RATE_LIMITED: 'rate_limited',
  INVALID_INPUT: 'invalid_input',
  PERMISSION_DENIED: 'permission_denied',
  COMMAND_EXECUTION: 'command_execution',
  UNKNOWN: 'unknown'
};

class ErrorHandler {
  /**
   * Classify an error based on its message or properties
   * @param {Error} error - The error to classify
   * @param {string} component - The component that generated the error
   * @returns {Object} - Classified error object
   */
  classifyError(error, component = 'unknown') {
    const errorMsg = error.message || '';
    const errorType = this.determineErrorType(error, errorMsg);
    
    return {
      type: errorType,
      component: component,
      message: errorMsg,
      original: error,
      timestamp: new Date().toISOString()
    };
  }
  
  /**
   * Determine the error type based on error and message
   * @param {Error} error - The original error
   * @param {string} message - Error message
   * @returns {string} - Error type
   */
  determineErrorType(error, message) {
    message = message.toLowerCase();
    
    // Check for timeout errors
    if (
      message.includes('timeout') || 
      message.includes('timed out') || 
      error.code === 'ETIMEDOUT'
    ) {
      return ERROR_TYPES.TIMEOUT;
    }
    
    // Check for connection refused
    if (
      message.includes('refused') || 
      message.includes('econnrefused') || 
      error.code === 'ECONNREFUSED'
    ) {
      return ERROR_TYPES.CONNECTION_REFUSED;
    }
    
    // Check for host unreachable
    if (
      message.includes('unreachable') || 
      message.includes('ehostunreach') || 
      error.code === 'EHOSTUNREACH'
    ) {
      return ERROR_TYPES.HOST_UNREACHABLE;
    }
    
    // Check for DNS resolution errors
    if (
      message.includes('dns') || 
      message.includes('resolve') || 
      message.includes('enotfound') || 
      error.code === 'ENOTFOUND'
    ) {
      return ERROR_TYPES.DNS_RESOLUTION;
    }
    
    // Check for firewall blocks
    if (
      message.includes('firewall') || 
      message.includes('filtered') || 
      message.includes('blocked')
    ) {
      return ERROR_TYPES.FIREWALL_BLOCK;
    }
    
    // Check for rate limiting
    if (
      message.includes('rate') || 
      message.includes('limit') || 
      message.includes('throttle')
    ) {
      return ERROR_TYPES.RATE_LIMITED;
    }
    
    // Check for permission issues
    if (
      message.includes('permission') || 
      message.includes('eacces') || 
      error.code === 'EACCES'
    ) {
      return ERROR_TYPES.PERMISSION_DENIED;
    }
    
    // Check for command execution errors
    if (
      message.includes('command') || 
      message.includes('spawn') || 
      message.includes('exec')
    ) {
      return ERROR_TYPES.COMMAND_EXECUTION;
    }
    
    // Check for invalid input
    if (
      message.includes('invalid') || 
      message.includes('malformed') || 
      message.includes('syntax')
    ) {
      return ERROR_TYPES.INVALID_INPUT;
    }
    
    // Default to unknown
    return ERROR_TYPES.UNKNOWN;
  }
  
  /**
   * Format an error for inclusion in scan output
   * @param {Object} error - Classified error object
   * @returns {Object} - Formatted error for output
   */
  formatErrorForOutput(error) {
    return {
      type: error.type || ERROR_TYPES.UNKNOWN,
      component: error.component || 'unknown',
      message: error.message || 'Unknown error',
      timestamp: error.timestamp || new Date().toISOString()
    };
  }
  
  /**
   * Create a scan status object based on error information
   * @param {Object} error - Classified error object
   * @param {string} component - The scan component (port_scan, http_analysis, etc.)
   * @returns {Object} - Scan status object
   */
  createScanStatus(error, component) {
    return {
      success: false,
      error_type: error.type || ERROR_TYPES.UNKNOWN,
      message: error.message || 'Unknown error',
      results_found: false
    };
  }
  
  /**
   * Get all defined error types
   * @returns {Object} - All error type constants
   */
  getErrorTypes() {
    return ERROR_TYPES;
  }
}

module.exports = ErrorHandler;
