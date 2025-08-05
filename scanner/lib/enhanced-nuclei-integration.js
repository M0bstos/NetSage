/**
 * Enhanced Nuclei Scanner Integration Example
 * 
 * This file demonstrates how to integrate the enhanced NucleiScanner with
 * the new NucleiTemplateManager for improved vulnerability scanning.
 */

const NucleiScanner = require('./nuclei');
const NucleiTemplateManager = require('./nucleiTemplateManager');
const path = require('path');
const fs = require('fs').promises;

/**
 * Enhanced scanner with template management
 */
class EnhancedNucleiScanner {
  /**
   * Create a new enhanced scanner instance
   * @param {Object} options Scanner options
   */
  constructor(options = {}) {
    // Initialize the template manager
    this.templateManager = new NucleiTemplateManager({
      nucleiPath: options.nucleiPath,
      templatesDir: options.templatesDir,
      verbose: options.verbose
    });
    
    // Initialize the scanner with basic options
    this.scanner = new NucleiScanner({
      nucleiPath: options.nucleiPath,
      timeout: options.timeout || 600000,
      outputDir: options.outputDir,
      rateLimit: options.rateLimit || 150,
      concurrency: options.concurrency || 25,
      bulkSize: options.bulkSize || 25,
      retries: options.retries || 3,
      autoUpdateTemplates: options.autoUpdateTemplates !== false,
      enableProgressTracking: options.enableProgressTracking !== false,
      verbose: options.verbose
    });
    
    // Store additional options
    this.options = options;
    this.initialized = false;
  }
  
  /**
   * Initialize the enhanced scanner
   * @returns {Promise<boolean>} True if initialization succeeds
   */
  async initialize() {
    try {
      console.log('Initializing enhanced Nuclei scanner...');
      
      // Initialize template manager
      const templateManagerInitialized = await this.templateManager.initialize();
      if (!templateManagerInitialized) {
        throw new Error('Failed to initialize template manager');
      }
      
      // Check if nuclei is available
      const nucleiAvailable = await this.scanner.isNucleiAvailable();
      if (!nucleiAvailable) {
        throw new Error('Nuclei is not installed or not available in PATH');
      }
      
      this.initialized = true;
      return true;
    } catch (error) {
      console.error('Failed to initialize enhanced Nuclei scanner:', error.message);
      return false;
    }
  }
  
  /**
   * Scan a target with enhanced template selection
   * @param {string} target Target URL to scan
   * @param {Object} options Scan options
   * @returns {Promise<Object>} Scan results
   */
  async scan(target, options = {}) {
    try {
      if (!this.initialized) {
        const initialized = await this.initialize();
        if (!initialized) {
          throw new Error('Scanner not initialized. Please call initialize() first');
        }
      }
      
      console.log(`Scanning target: ${target}`);
      
      // Check for WAF if option is enabled
      let wafDetected = false;
      let wafDetails = null;
      
      if (options.detectWaf !== false) {
        console.log('Checking for WAF protection...');
        const wafResult = await this.templateManager.detectWAF(target);
        
        if (wafResult.detected) {
          console.log(`WAF detected: ${wafResult.names.join(', ')}`);
          wafDetected = true;
          wafDetails = wafResult;
        } else {
          console.log('No WAF detected');
        }
      }
      
      // Select appropriate templates based on target and WAF status
      const templates = this.templateManager.selectTemplatesForTarget(target, {
        severity: options.severity || this.options.severity,
        categories: options.templates || this.options.templates,
        includeWaf: wafDetected
      });
      
      console.log(`Using templates: ${templates.join(', ')}`);
      
      // Prepare scan options
      const scanOptions = {
        ...this.options,
        templates: templates,
        severityLevel: options.severity || this.options.severity
      };
      
      // Run the scan with selected templates
      const results = await this.scanner.scan(target);
      
      // Enhance results with template information
      results.templates = {
        selected: templates,
        stats: this.templateManager.getTemplateStats()
      };
      
      // Add WAF information if detected
      if (wafDetected) {
        results.waf = wafDetails;
      }
      
      return results;
    } catch (error) {
      console.error(`Error scanning target ${target}:`, error.message);
      return {
        success: false,
        target,
        timestamp: new Date().toISOString(),
        error: error.message
      };
    }
  }
  
  /**
   * Get template statistics
   * @returns {Object} Template statistics
   */
  async getTemplateStats() {
    if (!this.initialized) {
      await this.initialize();
    }
    
    return this.templateManager.getTemplateStats();
  }
  
  /**
   * Create a custom template
   * @param {Object} templateData Template data
   * @returns {Promise<string>} Path to created template
   */
  async createCustomTemplate(templateData) {
    if (!this.initialized) {
      await this.initialize();
    }
    
    return this.templateManager.createCustomTemplate(templateData);
  }
  
  /**
   * List all custom templates
   * @returns {Promise<Array>} List of custom templates
   */
  async listCustomTemplates() {
    if (!this.initialized) {
      await this.initialize();
    }
    
    return this.templateManager.listCustomTemplates();
  }
  
  /**
   * Get scan progress information
   * @returns {Object} Scan progress data
   */
  getScanProgress() {
    return this.scanner.progressData;
  }
}

// Example usage
async function runExample() {
  console.log('Running Enhanced Nuclei Scanner Example');
  
  const scanner = new EnhancedNucleiScanner({
    verbose: true,
    severity: 'high' // Only scan for high and critical vulnerabilities
  });
  
  await scanner.initialize();
  
  // Example targets
  const targets = [
    'http://example.com',
    'http://testphp.vulnweb.com', // Test site with intentional vulnerabilities
  ];
  
  for (const target of targets) {
    console.log(`\nScanning target: ${target}`);
    
    const results = await scanner.scan(target, {
      detectWaf: true
    });
    
    console.log(`Scan completed for ${target}`);
    console.log(`Found ${results.findings?.length || 0} vulnerabilities`);
    
    // Save results to file
    const outputDir = path.join(__dirname, 'scan-results');
    if (!fs.existsSync(outputDir)) {
      await fs.mkdir(outputDir, { recursive: true });
    }
    
    const outputFile = path.join(outputDir, `enhanced-nuclei-${Date.now()}.json`);
    await fs.writeFile(outputFile, JSON.stringify(results, null, 2));
    
    console.log(`Results saved to: ${outputFile}`);
  }
  
  console.log('\nExample completed');
}

// Uncomment to run the example
// runExample().catch(console.error);

module.exports = EnhancedNucleiScanner;
