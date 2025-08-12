/**
 * Evasion Techniques Module
 * 
 * This module provides methods to enhance port scanning stealth and avoid detection
 * by implementing various Nmap evasion techniques.
 * 
 * Phase 4, Step 1 Implementation:
 * - IP Fragmentation
 * - Decoy Scan capabilities
 * - Source port manipulation
 * - Randomized scan order
 */

class EvasionTechniques {
  /**
   * Create a new EvasionTechniques instance
   * @param {Object} options - Options for evasion techniques
   * @param {boolean} options.enableFragmentation - Enable IP fragmentation
   * @param {boolean} options.enableDecoys - Enable decoy scans
   * @param {boolean} options.enableSourcePort - Enable source port manipulation
   * @param {boolean} options.enableRandomization - Enable randomized scanning
   */
  constructor(options = {}) {
    this.enableFragmentation = options.enableFragmentation !== false;
    this.enableDecoys = options.enableDecoys !== false;
    this.enableSourcePort = options.enableSourcePort !== false;
    this.enableRandomization = options.enableRandomization !== false;
    
    // Source ports commonly used for outgoing connections
    this.commonSourcePorts = [
      53,   // DNS
      80,   // HTTP
      443,  // HTTPS
      20,   // FTP data
      25    // SMTP
    ];
  }

  /**
   * Apply evasion techniques to Nmap arguments
   * @param {Array} nmapArgs - Current Nmap arguments array
   * @param {Object} options - Additional options
   * @param {string} options.evasionProfile - Evasion profile: 'minimal', 'moderate', 'aggressive'
   * @returns {Array} - Enhanced Nmap arguments with evasion techniques
   */
  applyEvasionTechniques(nmapArgs, options = {}) {
    const evasionProfile = options.evasionProfile || 'moderate';
    const techniques = [];
    
    // Apply different techniques based on the profile
    switch (evasionProfile) {
      case 'aggressive':
        return this.applyAggressiveEvasion(nmapArgs, options);
      case 'minimal':
        return this.applyMinimalEvasion(nmapArgs, options);
      case 'moderate':
      default:
        return this.applyModerateEvasion(nmapArgs, options);
    }
  }

  /**
   * Apply minimal evasion techniques (least likely to be detected but also least effective)
   * @param {Array} nmapArgs - Current Nmap arguments
   * @param {Object} options - Additional options
   * @returns {Array} - Enhanced Nmap arguments
   */
  applyMinimalEvasion(nmapArgs, options = {}) {
    // Just randomize scan order and use a short data length
    if (this.enableRandomization) {
      nmapArgs.push('--randomize-hosts');
    }
    
    // Add a small data payload to make packets look more legitimate
    nmapArgs.push('--data-length=8');
    
    return nmapArgs;
  }
  
  /**
   * Apply moderate evasion techniques (balanced approach)
   * @param {Array} nmapArgs - Current Nmap arguments
   * @param {Object} options - Additional options
   * @returns {Array} - Enhanced Nmap arguments
   */
  applyModerateEvasion(nmapArgs, options = {}) {
    // Apply IP fragmentation if enabled
    if (this.enableFragmentation) {
      nmapArgs.push('-f'); // Fragment packets
    }
    
    // Use a common source port if enabled
    if (this.enableSourcePort) {
      const sourcePort = this.getRandomCommonSourcePort();
      nmapArgs.push(`--source-port=${sourcePort}`);
    }
    
    // Randomize scan order
    if (this.enableRandomization) {
      nmapArgs.push('--randomize-hosts');
    }
    
    // Add a moderate data payload
    nmapArgs.push('--data-length=24');
    
    // Add timing adjustments
    nmapArgs.push('--scan-delay=100ms');
    
    return nmapArgs;
  }
  
  /**
   * Apply aggressive evasion techniques (most effective but may slow down scans)
   * @param {Array} nmapArgs - Current Nmap arguments
   * @param {Object} options - Additional options
   * @returns {Array} - Enhanced Nmap arguments
   */
  applyAggressiveEvasion(nmapArgs, options = {}) {
    // Apply IP fragmentation with higher fragment count
    if (this.enableFragmentation) {
      nmapArgs.push('-ff'); // More fragments
    }
    
    // Use decoys if enabled - generate 5 random IP decoys
    if (this.enableDecoys) {
      const decoys = this.generateDecoys(5);
      nmapArgs.push(`-D${decoys}`);
    }
    
    // Use a common source port if enabled
    if (this.enableSourcePort) {
      const sourcePort = this.getRandomCommonSourcePort();
      nmapArgs.push(`--source-port=${sourcePort}`);
    }
    
    // Randomize scan order and ports
    if (this.enableRandomization) {
      nmapArgs.push('--randomize-hosts');
      nmapArgs.push('--randomize-ports');
    }
    
    // Add a larger data payload
    nmapArgs.push('--data-length=56');
    
    // MAC spoofing (use a random vendor)
    nmapArgs.push('--spoof-mac=0');
    
    // Add scan delay for stealth
    nmapArgs.push('--scan-delay=250ms');
    
    return nmapArgs;
  }
  
  /**
   * Generate a list of decoy IP addresses
   * @param {number} count - Number of decoys to generate
   * @returns {string} - Comma-separated list of decoy IPs
   */
  generateDecoys(count = 5) {
    const decoys = [];
    
    // Generate realistic-looking IPs for major cloud providers
    const commonRanges = [
      ['13.32', '13.59'],   // AWS
      ['20.38', '20.72'],   // Azure
      ['34.64', '35.245'],  // GCP
      ['104.16', '104.31'], // Cloudflare
      ['172.64', '172.71']  // Other CDNs
    ];
    
    for (let i = 0; i < count; i++) {
      // Pick a random range
      const range = commonRanges[Math.floor(Math.random() * commonRanges.length)];
      
      // Generate a random IP in that range
      const firstOctet = range[0].split('.')[0];
      const secondOctet = range[0].split('.')[1];
      const thirdOctet = Math.floor(Math.random() * 256);
      const fourthOctet = Math.floor(Math.random() * 256);
      
      decoys.push(`${firstOctet}.${secondOctet}.${thirdOctet}.${fourthOctet}`);
    }
    
    // Add ME placeholder to put our real IP in a random position
    const insertPos = Math.floor(Math.random() * (decoys.length + 1));
    decoys.splice(insertPos, 0, 'ME');
    
    return decoys.join(',');
  }
  
  /**
   * Get a random common source port
   * @returns {number} - A common source port
   */
  getRandomCommonSourcePort() {
    return this.commonSourcePorts[
      Math.floor(Math.random() * this.commonSourcePorts.length)
    ];
  }
}

module.exports = EvasionTechniques;
