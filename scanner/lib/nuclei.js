/**
 * Nuclei Integration Module
 * 
 * This module integrates the Nuclei vulnerability scanner with the NetSage scanner.
 * It provides functionality to execute Nuclei scans and process the results.
 * 
 * The module supports Windows and Unix-based platforms and handles the differences
 * in how commands are executed on these platforms. For Windows, it uses a simplified
 * command approach that has been tested to work reliably.
 * 
 * The module parses JSONL (JSON Lines) output from Nuclei and formats the findings
 * into a standardized structure for further processing.
 */

const { exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const { promisify } = require('util');
const execPromise = promisify(exec);
const fsSync = require('fs');

class NucleiScanner {
  /**
   * Creates a new Nuclei scanner instance
   * @param {Object} options - Scanner options
   * @param {number} options.timeout - Timeout in milliseconds for scan operations (default: 10 minutes)
   * @param {string} options.outputDir - Directory to store scan results
   * @param {string|Array} options.templates - Template category or array of templates (default: 'technologies')
   * @param {string} options.nucleiPath - Path to nuclei executable (default: 'nuclei')
   */
  constructor(options = {}) {
    this.timeout = options.timeout || 600000; // Default 10 minutes (increase if needed)
    
    // Create absolute path to scan-results directory
    const rootDir = path.dirname(__dirname); // Go up one level from lib/ to scanner/
    this.outputDir = options.outputDir || path.join(rootDir, 'scan-results');
    console.log(`Output directory set to: ${this.outputDir}`);
    
    this.templates = options.templates || 'technologies'; // Default to just technologies template
    this.nucleiPath = options.nucleiPath || 'nuclei';
    
    // Default templates directory path (used for verification)
    this.templatesDir = options.templatesDir || null;
    if (!this.templatesDir) {
      // Try to determine templates directory based on OS
      if (process.platform === 'win32') {
        // Windows: Most likely in %USERPROFILE%\nuclei-templates
        this.templatesDir = path.join(process.env.USERPROFILE || '', 'nuclei-templates');
        
        // Check alternative locations if common on Windows
        if (!fsSync.existsSync(this.templatesDir)) {
          const altLocations = [
            path.join(process.env.USERPROFILE || '', '.nuclei', 'templates'),
            path.join(process.env.LOCALAPPDATA || '', 'nuclei-templates')
          ];
          
          for (const loc of altLocations) {
            if (fsSync.existsSync(loc)) {
              this.templatesDir = loc;
              break;
            }
          }
        }
      } else {
        // Linux/macOS: Default is in ~/.nuclei/templates
        this.templatesDir = path.join(process.env.HOME || '', '.nuclei', 'templates');
      }
    }
    
    // Additional scan options
    this.rateLimit = options.rateLimit || '150'; // Requests per second
    this.concurrency = options.concurrency || '25'; // Template concurrency
    this.bulkSize = options.bulkSize || '25'; // Hosts per request
    this.retries = options.retries || 1; // Number of retries for failed requests
    this.autoUpdateTemplates = options.autoUpdateTemplates !== false; // Auto update templates
  }

  /**
   * Check if nuclei is installed and accessible
   * @returns {Promise<boolean>} True if nuclei is available
   */
  async isNucleiAvailable() {
    try {
      // Try both execFile and exec approaches to be thorough
      let versionOutput = '';
      
      try {
        // First try execFile which is safer
        const { execFile } = require('child_process');
        const execFilePromise = promisify(execFile);
        const { stdout } = await execFilePromise(this.nucleiPath, ['-version'], { timeout: 30000 });
        versionOutput = stdout.trim();
      } catch (execFileError) {
        // If that fails, try exec as fallback
        const { stdout } = await execPromise(`"${this.nucleiPath}" -version`, { timeout: 30000 });
        versionOutput = stdout.trim();
      }
      
      console.log(`Found Nuclei version: ${versionOutput}`);
      
      // Check if templates exist by directly checking the template directory
      const templatesAvailable = await this.verifyTemplatesExist();
      
      // If templates don't exist and autoUpdate is enabled, update them
      if (!templatesAvailable) {
        if (this.autoUpdateTemplates) {
          console.log('Templates not found. Attempting to update templates...');
          await this.updateTemplates();
        } else {
          console.warn('Templates not found and auto-update is disabled. Nuclei may not work properly.');
        }
      }
      
      return true;
    } catch (error) {
      if (error.code === 'ENOENT') {
        console.error(`Nuclei is not available: The executable was not found at '${this.nucleiPath}'`);
      } else {
        console.error('Nuclei is not available:', error.message);
      }
      
      // Try running a simpler command just to check if the executable exists
      try {
        const { execSync } = require('child_process');
        execSync(`${this.nucleiPath}`, { timeout: 1000 });
        console.log('The nuclei executable exists but had an error with the version check.');
      } catch (simpleError) {
        if (simpleError.code !== 'ENOENT') {
          console.log('The nuclei executable exists but may not be working properly.');
        }
      }
      
      return false;
    }
  }
  
  /**
   * Verify if Nuclei templates exist in the expected directory
   * @returns {Promise<boolean>} True if templates exist
   */
  async verifyTemplatesExist() {
    try {
      // Check if templates directory exists
      try {
        await fs.access(this.templatesDir);
      } catch (err) {
        console.warn(`Templates directory not found: ${this.templatesDir}`);
        return false;
      }
      
      // Try to check templates availability via nuclei command first (most reliable)
      try {
        const { execSync } = require('child_process');
        const templatesOutput = execSync(`"${this.nucleiPath}" -tl`, { timeout: 30000 }).toString();
        
        if (templatesOutput.includes('templates') && templatesOutput.toLowerCase().includes('http/technologies')) {
          console.log('Templates are available via nuclei command');
          return true;
        }
      } catch (cmdError) {
        console.warn('Could not verify templates via nuclei command, checking file system...');
      }
      
      // Check for http/technologies directory which should exist
      try {
        const httpTechPath = path.join(this.templatesDir, 'http', 'technologies');
        await fs.access(httpTechPath);
        
        // Check for some specific templates
        const files = await fs.readdir(httpTechPath);
        
        // Check if there are any yaml files in the directory
        const templateCount = files.filter(f => f.endsWith('.yaml')).length;
        
        if (templateCount > 0) {
          console.log(`Found ${templateCount} technology templates in ${httpTechPath}`);
          return true;
        }
        
        console.warn(`No yaml templates found in ${httpTechPath}`);
        return false;
      } catch (err) {
        // Check for top-level technologies directory (alternative structure)
        try {
          const techPath = path.join(this.templatesDir, 'technologies');
          await fs.access(techPath);
          
          const files = await fs.readdir(techPath);
          const templateCount = files.filter(f => f.endsWith('.yaml')).length;
          
          if (templateCount > 0) {
            console.log(`Found ${templateCount} technology templates in ${techPath}`);
            return true;
          }
          
          console.warn(`No yaml templates found in ${techPath}`);
          return false;
        } catch (err2) {
          console.warn('Could not find templates in expected locations');
          return false;
        }
      }
    } catch (error) {
      console.warn(`Templates verification failed: ${error.message}`);
      return false;
    }
  }
  
  /**
   * Updates Nuclei templates
   * @returns {Promise<boolean>} True if update was successful
   */
  async updateTemplates() {
    console.log('Updating Nuclei templates...');
    try {
      // Use higher timeout for template update (can take a while)
      const updateTimeout = 120000; // 2 minutes
      
      // Try both execFile and exec approaches
      try {
        const { execFile } = require('child_process');
        const execFilePromise = promisify(execFile);
        const { stdout } = await execFilePromise(
          this.nucleiPath, 
          ['-update-templates'],
          { timeout: updateTimeout }
        );
        console.log('Templates update output:', stdout.trim());
      } catch (execFileError) {
        // If that fails, try exec as fallback
        const { stdout } = await execPromise(
          `"${this.nucleiPath}" -update-templates`,
          { timeout: updateTimeout }
        );
        console.log('Templates update output:', stdout.trim());
      }
      
      // Verify templates again after update
      const templatesExist = await this.verifyTemplatesExist();
      if (templatesExist) {
        console.log('Templates successfully updated');
        return true;
      } else {
        console.warn('Templates update completed but templates still not found');
        return false;
      }
    } catch (error) {
      console.error('Failed to update templates:', error.message);
      return false;
    }
  }

  /**
   * Prepare the output directory for scan results
   * @returns {Promise<string>} Path to the output JSON file
   */
  async prepareOutputDirectory() {
    try {
      // Ensure the output directory exists
      if (!fsSync.existsSync(this.outputDir)) {
        await fs.mkdir(this.outputDir, { recursive: true });
      }
      const outputFile = path.join(this.outputDir, `nuclei-${Date.now()}.json`);
      console.log(`Preparing output file: ${outputFile}`);
      return outputFile;
    } catch (error) {
      throw new Error(`Failed to create output directory: ${error.message}`);
    }
  }

  /**
   * Run a nuclei scan on the target URL
   * @param {string} target - URL to scan
   * @returns {Promise<Object>} Scan results
   */
  async scan(target) {
    try {
      // Check if nuclei is available
      const isAvailable = await this.isNucleiAvailable();
      if (!isAvailable) {
        throw new Error('Nuclei is not installed or not available in PATH');
      }

      // Prepare output file
      const outputFile = await this.prepareOutputDirectory();
      
      // Handle Windows and Unix systems differently
      const isWindows = process.platform === 'win32';
      
      console.log(`Scanning target ${target} with Nuclei...`);
      console.log(`Using templates: ${Array.isArray(this.templates) ? this.templates.join(',') : this.templates}`);
      
      // For Windows, use a simplified command with minimal arguments
      if (isWindows) {
        console.log('Using simplified command for Windows...');
        
        // This format has been tested to work reliably on Windows
        // Use both verbose and JSON output flags
        let command = `"${this.nucleiPath}" -u "${target}" -v -j -o "${outputFile}"`;
        
        // Add template parameter directly - simple form
        if (typeof this.templates === 'string' && this.templates) {
          command += ` -t "${this.templates}"`;
        } else if (Array.isArray(this.templates) && this.templates.length > 0) {
          // Join with comma for Windows
          command += ` -t "${this.templates.join(',')}"`;
        } else {
          command += ` -t "technologies"`;
        }
        
        // Add timeout flag to allow Nuclei to manage its own timeout
        command += ` -timeout 5`; // 5 minutes per template
        
        console.log(`Windows command: ${command}`);
        
        // Use execSync for better output capturing
        const { execSync } = require('child_process');
        let stdout = '';
        let stderr = '';
        
        try {
          console.log(`Running with timeout of ${this.timeout/1000} seconds...`);
          stdout = execSync(command, { 
            timeout: this.timeout,
            maxBuffer: 10 * 1024 * 1024 // 10MB buffer
          }).toString();
        } catch (execError) {
          stderr = execError.stderr ? execError.stderr.toString() : 'Execution error';
          if (execError.stdout) {
            stdout = execError.stdout.toString();
          }
        }
        
        console.log('Scan completed');
        
        // Parse the results
        return this.processResults(target, outputFile, stdout, stderr);
      } else {
        // For Unix systems, use execFile with array arguments
        const args = [
          '-u', target,
          '-silent',
          '-j',
          '-timeout', '5', // Per template timeout in minutes
          '-rate-limit', this.rateLimit,
          '-c', this.concurrency,
          '-bulk-size', this.bulkSize,
          '-retries', this.retries.toString(),
          '-output', outputFile
        ];
        
        // Add template argument
        if (Array.isArray(this.templates) && this.templates.length > 0) {
          args.push('-t', this.templates.join(','));
        } else if (typeof this.templates === 'string' && this.templates) {
          args.push('-t', this.templates);
        } else {
          args.push('-t', 'technologies');
        }
        
        console.log(`Unix command: ${this.nucleiPath} ${args.join(' ')}`);
        
        const { execFile } = require('child_process');
        const execFilePromise = promisify(execFile);
        
        const { stdout, stderr } = await execFilePromise(this.nucleiPath, args, {
          timeout: this.timeout,
          maxBuffer: 10 * 1024 * 1024
        });
        
        console.log('Scan completed');
        
        // Process the results
        return this.processResults(target, outputFile, stdout, stderr);
      }
    } catch (error) {
      // Format more detailed error info
      let errorMessage = error.message;
      
      // Check for specific error types
      if (error.code === 'ENOENT') {
        errorMessage = `Nuclei executable not found at "${this.nucleiPath}". Please install Nuclei or set the correct path.`;
      } else if (error.killed && error.signal === 'SIGTERM') {
        errorMessage = `Scan timed out after ${this.timeout/1000} seconds.`;
      }
      
      // Include stderr if available
      if (error.stderr) {
        errorMessage += `\nError output: ${error.stderr}`;
      }
      
      // Try running nuclei with just the -version flag to verify it works at all
      try {
        const { execSync } = require('child_process');
        const versionOutput = execSync(`"${this.nucleiPath}" -version`, { timeout: 10000 }).toString().trim();
        errorMessage += `\nNuclei version check works (${versionOutput}), but scan command failed.`;
        errorMessage += `\nThis might be due to invalid templates or other arguments.`;
        
        // Check templates
        console.log('Trying to check if templates are installed...');
        try {
          execSync(`"${this.nucleiPath}" -tl`, { timeout: 10000 });
          errorMessage += `\nTemplates check: Passed (templates are accessible)`;
        } catch (templateError) {
          errorMessage += `\nTemplates check: Failed (${templateError.message})`;
          errorMessage += `\nYou might need to run: nuclei -update-templates`;
          
          // Try to update templates automatically
          try {
            console.log('Attempting to update templates automatically...');
            execSync(`"${this.nucleiPath}" -update-templates`, { timeout: 120000 });
            errorMessage += `\nTemplate update attempted. Please try your scan again.`;
          } catch (updateError) {
            errorMessage += `\nFailed to auto-update templates: ${updateError.message}`;
          }
        }
      } catch (versionError) {
        errorMessage += `\nAttempting to run "nuclei -version" also failed: ${versionError.message}`;
      }
      
      console.error(`Nuclei scan error: ${errorMessage}`);
      
      return {
        success: false,
        target,
        timestamp: new Date().toISOString(),
        error: errorMessage,
        findings: [],
        debug: {
          command: error.cmd || `${this.nucleiPath} (command execution failed)`,
          error: error
        }
      };
    }
  }
  
  /**
   * Process scan results from file and stdout
   * @param {string} target - Target that was scanned
   * @param {string} outputFile - Path to output file
   * @param {string} stdout - Standard output from command
   * @param {string} stderr - Standard error from command
   * @returns {Object} Processed scan results
   */
  async processResults(target, outputFile, stdout, stderr) {
    // Try to read from the output file first, then fall back to stdout
    let jsonContent = '';
    let results = [];
    
    try {
      // First check if stdout contains results since Nuclei might output directly to stdout
      if (stdout && stdout.trim()) {
        console.log(`Processing results from stdout (${stdout.length} bytes)`);
        jsonContent = stdout;
        try {
          results = this.parseResults(jsonContent);
          console.log(`Completed Nuclei scan for ${target}: found ${results.length} findings from stdout`);
        } catch (stdoutError) {
          console.warn(`Error parsing stdout results: ${stdoutError.message}`);
        }
      }

      // If no results from stdout, try the output file
      if (results.length === 0) {
        try {
          // Use fs.existsSync to reliably check if the file exists
          if (fsSync.existsSync(outputFile)) {
            const fileStats = fsSync.statSync(outputFile);
            if (fileStats.size > 0) {
              jsonContent = await fs.readFile(outputFile, 'utf8');
              console.log(`Read ${jsonContent.length} bytes from output file ${outputFile}`);
              results = this.parseResults(jsonContent);
              console.log(`Completed Nuclei scan for ${target}: found ${results.length} findings from file`);
            } else {
              console.log(`Output file exists but is empty`);
            }
          } else {
            console.warn(`Output file does not exist: ${outputFile}`);
          }
        } catch (fileError) {
          console.warn(`Error processing output file: ${fileError.message}`);
        }
      }
      
      // Always ensure we have the output file for reference
      try {
        // Ensure the directory exists before writing
        const outputDir = path.dirname(outputFile);
        if (!fsSync.existsSync(outputDir)) {
          await fs.mkdir(outputDir, { recursive: true });
        }
        
        // Save the results or empty array if none
        const resultContent = results.length > 0 ? JSON.stringify(results, null, 2) : '[]';
        await fs.writeFile(outputFile, resultContent);
        console.log(`Saved ${results.length} results to file at ${outputFile}`);
      } catch (writeError) {
        console.error(`Error saving results to file: ${writeError.message}`);
      }
      
      // Process any findings from stdout if we have matches
      if (stdout && results.length === 0) {
        // Check for completed scan message and matches found
        const matchesRegex = /\[INF\]\s+Scan\s+completed\s+in\s+[\d.]+s\.\s+(\d+)\s+matches\s+found\./;
        const matchesMatch = stdout.match(matchesRegex);
        
        if (matchesMatch && parseInt(matchesMatch[1]) > 0) {
          console.log(`Found ${matchesMatch[1]} matches in stdout`);
          
          // Extract technology matches from stdout
          const stdoutFindings = this.parseStdoutForTechnologies(stdout);
          if (stdoutFindings.length > 0) {
            console.log(`Extracted ${stdoutFindings.length} findings from stdout text`);
            results = stdoutFindings;
          }
        }
      }

      return {
        success: true,
        target,
        timestamp: new Date().toISOString(),
        findings: results,
        outputFile,
        raw: {
          stdout,
          stderr
        }
      };
    } catch (error) {
      console.error(`Error processing results: ${error.message}`);
      return {
        success: false,
        target,
        timestamp: new Date().toISOString(),
        error: `Error processing results: ${error.message}`,
        findings: [],
        outputFile,
        raw: {
          stdout,
          stderr
        }
      };
    }
  }

  /**
   * Parse nuclei results from JSON or JSONL output
   * @param {string} rawResults - Raw output from nuclei
   * @returns {Array} Parsed findings
   */
  parseResults(rawResults) {
    try {
      if (!rawResults || typeof rawResults !== 'string' || !rawResults.trim()) {
        console.log('No results to parse (empty output)');
        return [];
      }
      
      console.log(`Raw results length: ${rawResults.length} bytes`);
      
      // First, try to parse as an array (could be from -json output)
      if (rawResults.trim().startsWith('[') && rawResults.trim().endsWith(']')) {
        try {
          const jsonArray = JSON.parse(rawResults);
          if (Array.isArray(jsonArray)) {
            console.log(`Found valid JSON array with ${jsonArray.length} findings`);
            return this.normalizeFindings(jsonArray);
          }
        } catch (arrayError) {
          console.log('Not a valid JSON array, trying JSONL format');
        }
      }
      
      // Otherwise, process as JSONL format (one JSON object per line)
      // Skip informational headers and keep only JSON lines
      const jsonLines = rawResults.split('\n')
        .filter(line => {
          // Keep only lines that look like JSON
          const trimmed = line.trim();
          return trimmed.startsWith('{') && 
                 (trimmed.includes('"template"') || trimmed.includes('"info"'));
        });
      
      console.log(`Found ${jsonLines.length} potential JSON lines`);
      
      const results = [];
      
      for (const line of jsonLines) {
        if (!line.trim()) continue;
        
        try {
          // Extract the JSON part from the line (handle potential prefixes/suffixes)
          const jsonStart = line.indexOf('{');
          const jsonEnd = line.lastIndexOf('}');
          
          if (jsonStart >= 0 && jsonEnd > jsonStart) {
            const jsonPart = line.substring(jsonStart, jsonEnd + 1);
            
            try {
              const finding = JSON.parse(jsonPart);
              if (this.isValidFinding(finding)) {
                results.push(this.normalizeFinding(finding));
              }
            } catch (jsonError) {
              // Skip invalid JSON
            }
          }
        } catch (lineError) {
          // Skip problem lines
        }
      }
      
      console.log(`Successfully parsed ${results.length} valid findings`);
      return results;
    } catch (error) {
      console.error(`Error parsing results: ${error.message}`);
      return [];
    }
  }
  
  /**
   * Check if a finding object is valid and contains required fields
   * @param {Object} finding - The finding object to validate
   * @returns {boolean} True if valid
   */
  isValidFinding(finding) {
    // Must have either info, template, or template-id
    return finding && (finding.info || finding.template || finding['template-id']);
  }
  
  /**
   * Normalize an array of findings to a consistent format
   * @param {Array} findings - Array of finding objects
   * @returns {Array} Normalized findings
   */
  normalizeFindings(findings) {
    if (!Array.isArray(findings)) return [];
    return findings.filter(f => this.isValidFinding(f)).map(f => this.normalizeFinding(f));
  }
  
  /**
   * Normalize a finding object to a consistent format
   * @param {Object} finding - Finding object from Nuclei
   * @returns {Object} Normalized finding
   */
  normalizeFinding(finding) {
    return {
      name: finding.info?.name || finding['matcher-name'] || finding['template-id'] || 'Unknown',
      severity: finding.info?.severity || 'unknown',
      type: finding.type || finding.template || finding['template-id'] || 'unknown',
      host: finding.host || finding['matched-at'] || '',
      url: finding['matched-at'] || finding.host || '',
      description: finding.info?.description || '',
      tags: finding.info?.tags || [],
      reference: finding.info?.reference || [],
      cve: this.extractCVE(finding),
      timestamp: finding.timestamp || new Date().toISOString()
    };
  }

  /**
   * Extract CVE information from a finding
   * @param {Object} finding - The nuclei finding
   * @returns {Array} Array of CVE identifiers
   */
  extractCVE(finding) {
    const cves = [];
    
    // Extract from tags
    if (finding.info?.tags) {
      finding.info.tags.forEach(tag => {
        if (tag.toLowerCase().startsWith('cve-')) {
          cves.push(tag);
        }
      });
    }
    
    // Extract from reference URLs
    if (finding.info?.reference) {
      finding.info.reference.forEach(ref => {
        const cveMatch = ref.match(/CVE-\d{4}-\d+/i);
        if (cveMatch && !cves.includes(cveMatch[0])) {
          cves.push(cveMatch[0]);
        }
      });
    }
    
    // Extract from name or description
    const nameDescMatch = (finding.info?.name || finding.info?.description || '')
      .match(/CVE-\d{4}-\d+/i);
    
    if (nameDescMatch && !cves.includes(nameDescMatch[0])) {
      cves.push(nameDescMatch[0]);
    }
    
    return cves;
  }

  /**
   * Run a basic test scan to verify Nuclei is working properly
   * @returns {Promise<boolean>} True if the test scan completed successfully
   */
  async testScan() {
    console.log('Running Nuclei test scan on example.com...');
    try {
      // Use a simple known target that should work reliably
      const testTarget = 'http://example.com';
      
      // Use a longer timeout for the test scan
      const originalTimeout = this.timeout;
      this.timeout = 120000; // 2 minutes for test
      
      // Run only with technologies template
      const originalTemplates = this.templates;
      this.templates = 'technologies';
      
      // Run the scan
      const result = await this.scan(testTarget);
      
      // Restore original settings
      this.timeout = originalTimeout;
      this.templates = originalTemplates;
      
      if (result.success) {
        console.log(`✅ Nuclei test scan completed successfully with ${result.findings.length} findings`);
        return true;
      } else {
        console.error(`❌ Nuclei test scan failed: ${result.error}`);
        return false;
      }
    } catch (error) {
      console.error(`❌ Nuclei test scan error: ${error.message}`);
      return false;
    }
  }

  /**
   * Parse stdout for technology matches when direct JSON parsing fails
   * @param {string} stdout - Standard output from nuclei command
   * @returns {Array} Array of findings extracted from stdout
   */
  parseStdoutForTechnologies(stdout) {
    if (!stdout || typeof stdout !== 'string') return [];
    
    const findings = [];
    
    // Look for lines with technology detection pattern like "[technology-detect] [http] [info] http://example.com"
    const lines = stdout.split('\n');
    
    // Debug info to help with pattern matching
    console.log(`Raw stdout length: ${stdout.length} bytes`);
    console.log(`Found ${lines.length} lines to process`);
    
    // Look for markers of successful detection
    const matchesRegex = /\[INF\]\s+Scan\s+completed\s+in\s+[\d.]+s\.\s+(\d+)\s+matches\s+found\./;
    const matchesMatch = stdout.match(matchesRegex);
    
    if (matchesMatch) {
      console.log(`Nuclei reported ${matchesMatch[1]} matches found`);
    }
    
    // Process each line for technology detection patterns
    for (const line of lines) {
      // Match patterns like [waf-detect:apachegeneric] [http] [info] http://scanme.nmap.org
      const match = line.match(/\[([^\]:]+)(?::([^\]]+))?\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+)/);
      if (match) {
        const [, templateName, subtypeName, protocol, severity, url] = match;
        
        // Create a finding object
        const finding = {
          name: subtypeName ? `${templateName} (${subtypeName})` : templateName,
          severity: severity || 'info',
          type: templateName,
          host: url.trim(),
          url: url.trim(),
          description: `Detected ${templateName}${subtypeName ? ` (${subtypeName})` : ''} on ${url.trim()}`,
          tags: [templateName, protocol],
          reference: [],
          cve: [],
          timestamp: new Date().toISOString()
        };
        
        findings.push(finding);
      }
    }
    
    console.log(`Found ${findings.length} technology findings in stdout`);
    return findings;
  }
}

module.exports = NucleiScanner;
