/**
 * Enhanced Nuclei Template Management Module (Phase 3, Step 2)
 * 
 * This module extends the NucleiScanner with advanced template management capabilities
 * to implement Phase 3, Step 2 of the NetSage scanner enhancement plan.
 * 
 * Key features:
 * 1. Comprehensive template selection with category-based filtering
 * 2. Severity filtering options for focused scanning
 * 3. Custom template management for common vulnerabilities
 * 4. WAF detection and evasion template integration
 * 5. Template verification and health checking
 */

const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { URL } = require('url');

class NucleiTemplateManager {
  /**
   * Create a new template manager instance
   * @param {Object} options Configuration options
   * @param {string} options.nucleiPath Path to nuclei executable
   * @param {string} options.templatesDir Path to templates directory
   * @param {boolean} options.verbose Enable verbose output
   */
  constructor(options = {}) {
    this.nucleiPath = options.nucleiPath || 'nuclei';
    this.templatesDir = options.templatesDir;
    this.verbose = options.verbose || false;
    
    // Initialize template categories with expanded definitions
    this.templateCategories = {
      // Basic categories for minimal scanning
      basic: ['technologies', 'ssl', 'http/headers', 'http/robots-txt'],
      
      // Security focused categories
      security: ['cves', 'vulnerabilities', 'exposures', 'misconfiguration', 'default-logins'],
      
      // Web categories for comprehensive web scanning
      web: ['cves', 'vulnerabilities', 'exposures', 'misconfiguration', 'http/exposed-panels'],
      
      // API specific categories
      api: ['api', 'takeovers', 'http/exposed-tokens', 'http/swagger', 'iot/api'],
      
      // Web application specific categories
      webapp: ['http/technologies', 'http/exposed-panels', 'http/exposures', 'http/vulnerabilities',
               'http/misconfiguration', 'http/exposed-panels', 'http/files'],
      
      // WAF detection and evasion templates
      waf: ['http/waf', 'http/firewall-bypass', 'http/waf-detection'],
      
      // Network services categories
      network: ['network', 'network/ftp', 'network/ssh', 'network/telnet', 'network/smtp'],
      
      // Empty categories to be populated during initialization
      all: [],
      custom: []
    };
    
    // Custom template directory for user-defined templates
    this.customTemplatesDir = null;
    
    // Severity level mappings
    this.severityLevels = {
      critical: ['critical'],
      high: ['critical', 'high'],
      medium: ['critical', 'high', 'medium'],
      low: ['critical', 'high', 'medium', 'low'],
      info: ['critical', 'high', 'medium', 'low', 'info'],
      all: ['critical', 'high', 'medium', 'low', 'info', 'unknown']
    };
    
    // Template statistics for optimization
    this.templateStats = {
      totalTemplates: 0,
      categoryCounts: {},
      severityCounts: {},
      lastUpdated: null
    };
  }
  
  /**
   * Initialize the template manager
   * @returns {Promise<boolean>} True if initialization succeeds
   */
  async initialize() {
    try {
      // Detect templates directory if not provided
      if (!this.templatesDir) {
        await this.detectTemplatesDirectory();
      }
      
      // Set up custom templates directory
      this.customTemplatesDir = path.join(this.templatesDir, 'custom');
      
      // Ensure custom templates directory exists
      await this.ensureCustomTemplatesDir();
      
      // Discover all available templates
      await this.discoverTemplates();
      
      // Update template statistics
      await this.updateTemplateStats();
      
      return true;
    } catch (error) {
      console.error('Failed to initialize template manager:', error.message);
      return false;
    }
  }
  
  /**
   * Detect the templates directory based on platform
   * @private
   */
  async detectTemplatesDirectory() {
    // Try to determine templates directory based on OS
    if (process.platform === 'win32') {
      // Windows: Most likely in %USERPROFILE%\nuclei-templates
      this.templatesDir = path.join(process.env.USERPROFILE || '', 'nuclei-templates');
      
      // Check alternative locations if common on Windows
      if (!fsSync.existsSync(this.templatesDir)) {
        const altLocations = [
          path.join(process.env.USERPROFILE || '', '.nuclei', 'templates'),
          path.join(process.env.LOCALAPPDATA || '', 'nuclei-templates'),
          path.join(process.env.APPDATA || '', 'nuclei-templates')
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
      
      // Check alternative locations for Linux
      if (!fsSync.existsSync(this.templatesDir)) {
        const altLocations = [
          '/usr/local/share/nuclei-templates',
          '/opt/nuclei-templates'
        ];
        
        for (const loc of altLocations) {
          if (fsSync.existsSync(loc)) {
            this.templatesDir = loc;
            break;
          }
        }
      }
    }
    
    if (this.verbose) {
      console.log(`Templates directory detected at: ${this.templatesDir}`);
    }
    
    if (!fsSync.existsSync(this.templatesDir)) {
      throw new Error(`Templates directory not found: ${this.templatesDir}`);
    }
  }
  
  /**
   * Ensure custom templates directory exists
   * @private
   */
  async ensureCustomTemplatesDir() {
    try {
      if (!fsSync.existsSync(this.customTemplatesDir)) {
        await fs.mkdir(this.customTemplatesDir, { recursive: true });
        
        // Create README file explaining the purpose of the directory
        const readmePath = path.join(this.customTemplatesDir, 'README.md');
        await fs.writeFile(readmePath, 
          '# Custom Nuclei Templates\n\n' +
          'This directory contains custom templates for Nuclei vulnerability scanner.\n' +
          'Templates in this directory will be automatically included in scans when using the "custom" category.\n\n' +
          '## Template Structure\n\n' +
          'Each template should follow the Nuclei template format. See https://nuclei.projectdiscovery.io/templating-guide/ for details.\n'
        );
        
        if (this.verbose) {
          console.log(`Created custom templates directory at ${this.customTemplatesDir}`);
        }
      }
      
      return true;
    } catch (error) {
      console.error('Failed to ensure custom templates directory:', error.message);
      return false;
    }
  }
  
  /**
   * Discover all available templates and categories
   * @private
   */
  async discoverTemplates() {
    try {
      if (this.verbose) {
        console.log('Discovering available templates...');
      }
      
      // Use nuclei's template list command
      let templateListOutput = '';
      
      try {
        templateListOutput = execSync(`"${this.nucleiPath}" -tl`, { timeout: 30000 }).toString();
      } catch (error) {
        console.warn('Failed to get template list:', error.message);
        
        // Fall back to filesystem-based discovery
        await this.discoverTemplatesFromFileSystem();
        return;
      }
      
      // Parse template categories from the output
      const categories = new Set();
      const lines = templateListOutput.split('\n');
      
      for (const line of lines) {
        if (line.includes('templates')) {
          // Extract category names
          const match = line.match(/\[([^\]]+)\]/);
          if (match && match[1]) {
            categories.add(match[1].trim());
          }
        }
      }
      
      // Update the all category with all discovered templates
      if (categories.size > 0) {
        this.templateCategories.all = Array.from(categories);
        
        if (this.verbose) {
          console.log(`Discovered ${this.templateCategories.all.length} template categories`);
        }
      }
    } catch (error) {
      console.error('Error discovering templates:', error.message);
      
      // Fall back to filesystem-based discovery
      await this.discoverTemplatesFromFileSystem();
    }
  }
  
  /**
   * Discover templates by scanning the filesystem
   * @private
   */
  async discoverTemplatesFromFileSystem() {
    try {
      if (this.verbose) {
        console.log('Discovering templates from file system...');
      }
      
      // Get all directories in the templates folder
      const entries = await fs.readdir(this.templatesDir, { withFileTypes: true });
      const categories = new Set();
      
      // Process top-level directories as categories
      for (const entry of entries) {
        if (entry.isDirectory()) {
          categories.add(entry.name);
          
          // Check for subdirectories (like http/technologies)
          try {
            const subEntries = await fs.readdir(path.join(this.templatesDir, entry.name), { withFileTypes: true });
            for (const subEntry of subEntries) {
              if (subEntry.isDirectory()) {
                categories.add(`${entry.name}/${subEntry.name}`);
              }
            }
          } catch (err) {
            // Ignore errors for subdirectories
          }
        }
      }
      
      // Update the all category with all discovered templates
      if (categories.size > 0) {
        this.templateCategories.all = Array.from(categories);
        
        if (this.verbose) {
          console.log(`Discovered ${this.templateCategories.all.length} template categories from file system`);
        }
      }
    } catch (error) {
      console.error('Error discovering templates from file system:', error.message);
    }
  }
  
  /**
   * Update template statistics
   * @private
   */
  async updateTemplateStats() {
    try {
      const stats = {
        totalTemplates: 0,
        categoryCounts: {},
        severityCounts: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
          unknown: 0
        },
        lastUpdated: new Date()
      };
      
      // Try to get template stats using nuclei command
      try {
        const output = execSync(`"${this.nucleiPath}" -tl -stats`, { timeout: 30000 }).toString();
        
        // Parse total templates
        const totalMatch = output.match(/Total templates: (\d+)/);
        if (totalMatch && totalMatch[1]) {
          stats.totalTemplates = parseInt(totalMatch[1], 10);
        }
        
        // Parse severity counts
        const severityMatches = output.match(/Severity: \[(.*?)\]/g);
        if (severityMatches) {
          for (const match of severityMatches) {
            const severityMatch = match.match(/Severity: \[(.*?)\] \[(\d+)\]/);
            if (severityMatch && severityMatch[1] && severityMatch[2]) {
              const severity = severityMatch[1].toLowerCase();
              const count = parseInt(severityMatch[2], 10);
              
              if (stats.severityCounts.hasOwnProperty(severity)) {
                stats.severityCounts[severity] = count;
              }
            }
          }
        }
        
        // Parse category counts
        const lines = output.split('\n');
        for (const line of lines) {
          if (line.includes('templates')) {
            // Extract category and count
            const categoryMatch = line.match(/\[([^\]]+)\]/);
            const countMatch = line.match(/\[(\d+) templates\]/);
            
            if (categoryMatch && categoryMatch[1] && countMatch && countMatch[1]) {
              const category = categoryMatch[1].trim();
              const count = parseInt(countMatch[1], 10);
              stats.categoryCounts[category] = count;
            }
          }
        }
      } catch (error) {
        console.warn('Failed to get template stats from nuclei command:', error.message);
        
        // Fall back to file system counting
        await this.updateTemplateStatsFromFileSystem(stats);
      }
      
      this.templateStats = stats;
      
      if (this.verbose) {
        console.log(`Template stats updated: ${stats.totalTemplates} templates, last updated: ${stats.lastUpdated.toISOString()}`);
      }
      
      return stats;
    } catch (error) {
      console.error('Error updating template stats:', error.message);
      return this.templateStats;
    }
  }
  
  /**
   * Update template statistics by scanning the file system
   * @param {Object} stats Statistics object to update
   * @private
   */
  async updateTemplateStatsFromFileSystem(stats) {
    try {
      let totalTemplates = 0;
      
      // Helper function to recursively count YAML files
      const countTemplates = async (dir, category = null) => {
        let count = 0;
        
        try {
          const entries = await fs.readdir(dir, { withFileTypes: true });
          
          for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            
            if (entry.isDirectory()) {
              // Create subcategory name
              const subCategory = category ? 
                `${category}/${entry.name}` : 
                entry.name;
              
              // Recursively count templates in subdirectory
              const subCount = await countTemplates(fullPath, subCategory);
              count += subCount;
            } else if (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) {
              // Count YAML files as templates
              count++;
              totalTemplates++;
              
              // Try to determine severity from file content
              // This is a simple approach and may not be accurate for all templates
              try {
                const content = await fs.readFile(fullPath, 'utf8');
                
                // Look for severity in the content
                const severityMatch = content.match(/severity:\s*([a-z]+)/i);
                if (severityMatch && severityMatch[1]) {
                  const severity = severityMatch[1].toLowerCase();
                  
                  if (stats.severityCounts.hasOwnProperty(severity)) {
                    stats.severityCounts[severity]++;
                  } else {
                    stats.severityCounts.unknown++;
                  }
                } else {
                  stats.severityCounts.unknown++;
                }
              } catch (err) {
                // If can't read file, count as unknown severity
                stats.severityCounts.unknown++;
              }
            }
          }
          
          // Update category count if category is defined
          if (category && count > 0) {
            stats.categoryCounts[category] = count;
          }
          
          return count;
        } catch (err) {
          console.warn(`Error counting templates in ${dir}:`, err.message);
          return 0;
        }
      };
      
      // Start counting from the templates directory
      await countTemplates(this.templatesDir);
      
      // Update total templates count
      stats.totalTemplates = totalTemplates;
      
      if (this.verbose) {
        console.log(`Template stats updated from file system: ${totalTemplates} templates`);
      }
    } catch (error) {
      console.error('Error updating template stats from file system:', error.message);
    }
  }
  
  /**
   * Get available template categories
   * @returns {Object} Template categories
   */
  getTemplateCategories() {
    return this.templateCategories;
  }
  
  /**
   * Get template statistics
   * @returns {Object} Template statistics
   */
  getTemplateStats() {
    return this.templateStats;
  }
  
  /**
   * Select templates based on target and severity level
   * @param {string} target Target URL or hostname
   * @param {Object} options Selection options
   * @param {string} options.severity Minimum severity level
   * @param {Array|string} options.categories Template categories to use
   * @param {boolean} options.includeWaf Include WAF detection templates
   * @returns {Array} Selected template categories
   */
  selectTemplatesForTarget(target, options = {}) {
    const severity = options.severity || null;
    const customCategories = options.categories || null;
    const includeWaf = options.includeWaf !== false; // Default to true
    
    // If categories are explicitly provided, use them
    if (customCategories) {
      const selectedCategories = Array.isArray(customCategories) ? 
        customCategories : [customCategories];
      
      // Always add custom templates if they exist
      if (fsSync.existsSync(this.customTemplatesDir)) {
        const customFiles = fsSync.readdirSync(this.customTemplatesDir)
          .filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));
        
        if (customFiles.length > 0 && !selectedCategories.includes('custom')) {
          selectedCategories.push('custom');
        }
      }
      
      // Add WAF detection templates if requested
      if (includeWaf && !selectedCategories.some(c => c.includes('waf'))) {
        selectedCategories.push(...this.templateCategories.waf);
      }
      
      return selectedCategories;
    }
    
    // Auto-select templates based on target
    let selectedCategories = [];
    
    try {
      // Parse URL if possible
      let urlObj;
      try {
        urlObj = new URL(target);
      } catch (e) {
        // If parsing fails, try adding http:// prefix
        try {
          urlObj = new URL(`http://${target}`);
        } catch (e2) {
          if (this.verbose) {
            console.warn('Could not parse target as URL, using basic templates');
          }
          selectedCategories = [...this.templateCategories.basic];
        }
      }
      
      if (urlObj) {
        // Extract hostname and path
        const { hostname, pathname, protocol } = urlObj;
        
        // API endpoint detection
        if (pathname && (
            pathname.includes('/api') || 
            pathname.includes('/v1') || 
            pathname.includes('/v2') ||
            pathname.includes('/rest') ||
            pathname.includes('/graphql')
           )) {
          if (this.verbose) {
            console.log(`Target appears to be an API endpoint, using API templates`);
          }
          selectedCategories = [...this.templateCategories.api];
        }
        // Web application detection (has non-root path)
        else if (pathname && pathname !== '/' && pathname.length > 1) {
          if (this.verbose) {
            console.log(`Target appears to be a web application, using webapp templates`);
          }
          selectedCategories = [...this.templateCategories.webapp];
        }
        // Standard web target
        else {
          if (this.verbose) {
            console.log(`Using standard web templates for target`);
          }
          selectedCategories = [...this.templateCategories.web];
        }
        
        // Add security templates
        selectedCategories.push(...this.templateCategories.security);
      }
      
      // Always add custom templates if they exist
      if (fsSync.existsSync(this.customTemplatesDir)) {
        const customFiles = fsSync.readdirSync(this.customTemplatesDir)
          .filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));
        
        if (customFiles.length > 0 && !selectedCategories.includes('custom')) {
          selectedCategories.push('custom');
        }
      }
      
      // Add WAF detection templates if requested
      if (includeWaf) {
        selectedCategories.push(...this.templateCategories.waf);
      }
      
      // Remove duplicates
      selectedCategories = [...new Set(selectedCategories)];
      
      if (this.verbose) {
        console.log(`Selected template categories for ${target}:`, selectedCategories);
      }
      
      return selectedCategories;
    } catch (error) {
      console.warn(`Error selecting templates for target: ${error.message}`);
      // Fallback to basic templates
      return [...this.templateCategories.basic];
    }
  }
  
  /**
   * Create a custom template for common vulnerabilities
   * @param {Object} templateData Template data
   * @param {string} templateData.name Template name
   * @param {string} templateData.author Author name
   * @param {string} templateData.description Template description
   * @param {string} templateData.severity Severity level (info, low, medium, high, critical)
   * @param {Object} templateData.match Matching criteria
   * @returns {Promise<string>} Path to created template
   */
  async createCustomTemplate(templateData) {
    try {
      // Validate required fields
      if (!templateData.name || !templateData.description || !templateData.severity) {
        throw new Error('Missing required template fields: name, description, and severity are required');
      }
      
      // Generate template filename (sanitize name for file system use)
      const sanitizedName = templateData.name
        .toLowerCase()
        .replace(/[^a-z0-9-]/g, '-')
        .replace(/-{2,}/g, '-') // Replace multiple hyphens with a single one
        .replace(/^-|-$/g, ''); // Remove leading/trailing hyphens
      
      const templateFileName = `${sanitizedName}.yaml`;
      const templatePath = path.join(this.customTemplatesDir, templateFileName);
      
      // Check if template already exists
      if (fsSync.existsSync(templatePath)) {
        throw new Error(`Template with name ${templateFileName} already exists`);
      }
      
      // Generate template content in YAML format
      let templateContent = `id: ${sanitizedName}\n`;
      templateContent += `info:\n`;
      templateContent += `  name: ${templateData.name}\n`;
      templateContent += `  author: ${templateData.author || 'NetSage Scanner'}\n`;
      templateContent += `  severity: ${templateData.severity.toLowerCase()}\n`;
      templateContent += `  description: ${templateData.description}\n`;
      templateContent += `  created: ${new Date().toISOString().split('T')[0]}\n\n`;
      
      // Add requests section
      templateContent += `requests:\n`;
      templateContent += `  - method: GET\n`;
      
      // Add path handling if provided
      if (templateData.path) {
        templateContent += `    path:\n`;
        if (Array.isArray(templateData.path)) {
          for (const p of templateData.path) {
            templateContent += `      - ${p}\n`;
          }
        } else {
          templateContent += `      - ${templateData.path}\n`;
        }
      } else {
        templateContent += `    path:\n`;
        templateContent += `      - "{{BaseURL}}"\n`;
      }
      
      // Add matchers based on type
      templateContent += `    matchers:\n`;
      
      if (templateData.match) {
        if (templateData.match.status) {
          templateContent += `      - type: status\n`;
          templateContent += `        status:\n`;
          if (Array.isArray(templateData.match.status)) {
            for (const status of templateData.match.status) {
              templateContent += `          - ${status}\n`;
            }
          } else {
            templateContent += `          - ${templateData.match.status}\n`;
          }
        }
        
        if (templateData.match.words) {
          templateContent += `      - type: word\n`;
          templateContent += `        words:\n`;
          if (Array.isArray(templateData.match.words)) {
            for (const word of templateData.match.words) {
              templateContent += `          - "${word}"\n`;
            }
          } else {
            templateContent += `          - "${templateData.match.words}"\n`;
          }
        }
        
        if (templateData.match.regex) {
          templateContent += `      - type: regex\n`;
          templateContent += `        regex:\n`;
          if (Array.isArray(templateData.match.regex)) {
            for (const regex of templateData.match.regex) {
              templateContent += `          - "${regex}"\n`;
            }
          } else {
            templateContent += `          - "${templateData.match.regex}"\n`;
          }
        }
      } else {
        // Default to status code matcher
        templateContent += `      - type: status\n`;
        templateContent += `        status:\n`;
        templateContent += `          - 200\n`;
      }
      
      // Write template file
      await fs.writeFile(templatePath, templateContent);
      
      if (this.verbose) {
        console.log(`Created custom template: ${templatePath}`);
      }
      
      // Update custom template category
      if (!this.templateCategories.custom.includes('custom')) {
        this.templateCategories.custom.push('custom');
      }
      
      return templatePath;
    } catch (error) {
      console.error('Error creating custom template:', error.message);
      throw error;
    }
  }
  
  /**
   * List all custom templates
   * @returns {Promise<Array>} List of custom templates
   */
  async listCustomTemplates() {
    try {
      // Ensure custom templates directory exists
      if (!fsSync.existsSync(this.customTemplatesDir)) {
        await this.ensureCustomTemplatesDir();
        return [];
      }
      
      // Get all yaml files in the custom templates directory
      const files = await fs.readdir(this.customTemplatesDir);
      const templateFiles = files.filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));
      
      const templates = [];
      
      // Read each template file and extract metadata
      for (const file of templateFiles) {
        try {
          const templatePath = path.join(this.customTemplatesDir, file);
          const content = await fs.readFile(templatePath, 'utf8');
          
          // Extract basic metadata using regex
          const nameMatch = content.match(/name:\s*(.+)/);
          const severityMatch = content.match(/severity:\s*(.+)/);
          const descMatch = content.match(/description:\s*(.+)/);
          const authorMatch = content.match(/author:\s*(.+)/);
          
          templates.push({
            filename: file,
            path: templatePath,
            name: nameMatch ? nameMatch[1].trim() : file,
            severity: severityMatch ? severityMatch[1].trim() : 'unknown',
            description: descMatch ? descMatch[1].trim() : '',
            author: authorMatch ? authorMatch[1].trim() : 'unknown'
          });
        } catch (err) {
          console.warn(`Error reading custom template ${file}:`, err.message);
        }
      }
      
      return templates;
    } catch (error) {
      console.error('Error listing custom templates:', error.message);
      return [];
    }
  }
  
  /**
   * Delete a custom template
   * @param {string} templateName Name of the template file to delete
   * @returns {Promise<boolean>} True if deletion was successful
   */
  async deleteCustomTemplate(templateName) {
    try {
      // Sanitize template name to prevent path traversal
      const filename = path.basename(templateName);
      const templatePath = path.join(this.customTemplatesDir, filename);
      
      // Check if template exists
      if (!fsSync.existsSync(templatePath)) {
        throw new Error(`Template ${filename} does not exist`);
      }
      
      // Delete the template file
      await fs.unlink(templatePath);
      
      if (this.verbose) {
        console.log(`Deleted custom template: ${templatePath}`);
      }
      
      return true;
    } catch (error) {
      console.error('Error deleting custom template:', error.message);
      return false;
    }
  }
  
  /**
   * Verify template syntax
   * @param {string} templatePath Path to template file
   * @returns {Promise<boolean>} True if template syntax is valid
   */
  async verifyTemplateSyntax(templatePath) {
    try {
      // Use nuclei's template validation
      execSync(`"${this.nucleiPath}" -validate -t "${templatePath}"`, { timeout: 30000 });
      return true;
    } catch (error) {
      console.error(`Template syntax validation failed for ${templatePath}:`, error.message);
      return false;
    }
  }
  
  /**
   * Get template suggestions for a given URL
   * @param {string} url Target URL
   * @returns {Promise<Object>} Template suggestions
   */
  async getTemplateSuggestions(url) {
    try {
      // Parse URL
      let urlObj;
      try {
        urlObj = new URL(url);
      } catch (e) {
        // If parsing fails, try adding http:// prefix
        try {
          urlObj = new URL(`http://${url}`);
        } catch (e2) {
          throw new Error('Invalid URL format');
        }
      }
      
      // Extract hostname and path
      const { hostname, pathname, protocol } = urlObj;
      
      // Suggestions based on URL analysis
      const suggestions = {
        recommended: [],
        additional: [],
        severe: []
      };
      
      // Add technology detection as a base recommendation
      suggestions.recommended.push('technologies');
      
      // Check for common CMS paths
      if (pathname.includes('/wp-') || pathname.includes('/wordpress')) {
        suggestions.recommended.push('http/wordpress');
        suggestions.severe.push('http/wordpress-detect');
      }
      if (pathname.includes('/joomla')) {
        suggestions.recommended.push('http/joomla');
      }
      if (pathname.includes('/drupal')) {
        suggestions.recommended.push('http/drupal');
      }
      
      // Check for API endpoints
      if (pathname.includes('/api') || 
          pathname.includes('/v1') || 
          pathname.includes('/v2') ||
          pathname.includes('/rest') ||
          pathname.includes('/graphql')) {
        suggestions.recommended.push('api');
        suggestions.recommended.push('http/exposed-tokens');
        suggestions.severe.push('http/api');
      }
      
      // Add security templates for all targets
      suggestions.additional.push('vulnerabilities');
      suggestions.additional.push('cves');
      suggestions.additional.push('misconfiguration');
      
      // Add severe vulnerability templates
      suggestions.severe.push('default-logins');
      suggestions.severe.push('exposures');
      
      // Add WAF detection for all web targets
      suggestions.additional.push('http/waf');
      
      return suggestions;
    } catch (error) {
      console.error('Error getting template suggestions:', error.message);
      return { recommended: ['technologies'], additional: [], severe: [] };
    }
  }
  
  /**
   * Get templates by severity level
   * @param {string} severityLevel Minimum severity level
   * @returns {Array} Template categories filtered by severity
   */
  getTemplatesBySeverity(severityLevel) {
    try {
      // Default to all severities if not specified
      if (!severityLevel || !this.severityLevels[severityLevel]) {
        return ['critical', 'high', 'medium', 'low', 'info'];
      }
      
      // Return selected severity levels
      return this.severityLevels[severityLevel];
    } catch (error) {
      console.error('Error getting templates by severity:', error.message);
      return ['critical', 'high', 'medium', 'low', 'info']; // Return all by default
    }
  }
  
  /**
   * Import a template from a URL or file
   * @param {string} source URL or file path of the template
   * @returns {Promise<string>} Path to imported template
   */
  async importTemplate(source) {
    try {
      let templateContent;
      
      // Check if source is a URL
      if (source.startsWith('http://') || source.startsWith('https://')) {
        // Download template from URL
        const response = await fetch(source);
        
        if (!response.ok) {
          throw new Error(`Failed to download template: ${response.statusText}`);
        }
        
        templateContent = await response.text();
      } else {
        // Read template from file
        templateContent = await fs.readFile(source, 'utf8');
      }
      
      // Extract template name from content
      const nameMatch = templateContent.match(/name:\s*(.+)/);
      let templateName;
      
      if (nameMatch && nameMatch[1]) {
        // Generate filename from template name
        templateName = nameMatch[1].trim()
          .toLowerCase()
          .replace(/[^a-z0-9-]/g, '-')
          .replace(/-{2,}/g, '-')
          .replace(/^-|-$/g, '') + '.yaml';
      } else {
        // Use a random name if name not found
        templateName = `imported-template-${Date.now()}.yaml`;
      }
      
      const templatePath = path.join(this.customTemplatesDir, templateName);
      
      // Write template to custom templates directory
      await fs.writeFile(templatePath, templateContent);
      
      // Verify template syntax
      const isValid = await this.verifyTemplateSyntax(templatePath);
      
      if (!isValid) {
        // If validation failed, delete the template
        try {
          await fs.unlink(templatePath);
        } catch (err) {
          // Ignore deletion errors
        }
        throw new Error(`Invalid template syntax: ${templateName}`);
      }
      
      if (this.verbose) {
        console.log(`Imported template: ${templatePath}`);
      }
      
      // Update custom template category if needed
      if (!this.templateCategories.custom.includes('custom')) {
        this.templateCategories.custom.push('custom');
      }
      
      return templatePath;
    } catch (error) {
      console.error('Error importing template:', error.message);
      throw error;
    }
  }
  
  /**
   * Check if WAF is detected for a target URL
   * @param {string} url Target URL
   * @returns {Promise<Object>} WAF detection results
   */
  async detectWAF(url) {
    try {
      // Use nuclei to run WAF detection templates
      const outputFile = path.join(this.templatesDir, `waf-detection-${Date.now()}.json`);
      
      // Run nuclei with WAF detection templates
      execSync(`"${this.nucleiPath}" -u "${url}" -t "http/waf" -j -o "${outputFile}"`, { timeout: 60000 });
      
      // Check if output file exists
      if (!fsSync.existsSync(outputFile)) {
        return { detected: false, details: null };
      }
      
      // Read and parse results
      const results = await fs.readFile(outputFile, 'utf8');
      
      // Clean up output file
      try {
        await fs.unlink(outputFile);
      } catch (err) {
        // Ignore deletion errors
      }
      
      // If no results, WAF not detected
      if (!results || results.trim() === '') {
        return { detected: false, details: null };
      }
      
      // Parse JSON lines
      const findings = [];
      const lines = results.split('\n').filter(line => line.trim() !== '');
      
      for (const line of lines) {
        try {
          const finding = JSON.parse(line);
          findings.push(finding);
        } catch (err) {
          // Skip invalid JSON lines
        }
      }
      
      // If findings exist, WAF detected
      if (findings.length > 0) {
        const wafNames = findings.map(f => f.info?.name || 'Unknown WAF').filter(Boolean);
        
        return {
          detected: true,
          names: [...new Set(wafNames)], // Deduplicate names
          details: findings
        };
      }
      
      return { detected: false, details: null };
    } catch (error) {
      console.error('Error detecting WAF:', error.message);
      return { detected: false, error: error.message };
    }
  }
  
  /**
   * Generate a command string with template selection
   * @param {string} target Target URL
   * @param {string} outputFile Output file path
   * @param {Object} options Scan options
   * @returns {string} Command string
   */
  generateTemplateCommand(target, outputFile, options = {}) {
    try {
      // Extract options
      const templates = options.templates || this.selectTemplatesForTarget(target, options);
      const severity = options.severity || null;
      const timeout = options.timeout || 5; // Template timeout in minutes
      const rateLimit = options.rateLimit || 150;
      const concurrency = options.concurrency || 25;
      const bulkSize = options.bulkSize || 25;
      const retries = options.retries || 3;
      
      // Start building command
      let command = `"${this.nucleiPath}" -u "${target}" -j -o "${outputFile}"`;
      
      // Add templates
      if (Array.isArray(templates) && templates.length > 0) {
        command += ` -t "${templates.join(',')}"`;
      } else if (typeof templates === 'string' && templates) {
        command += ` -t "${templates}"`;
      } else {
        command += ` -t "technologies"`;
      }
      
      // Add severity filter if specified
      if (severity && this.severityLevels[severity]) {
        command += ` -severity "${severity}"`;
      }
      
      // Add scan parameters
      command += ` -timeout ${timeout}`;
      command += ` -rate-limit ${rateLimit}`;
      command += ` -c ${concurrency}`;
      command += ` -bulk-size ${bulkSize}`;
      command += ` -retries ${retries}`;
      
      // Add progress tracking
      command += ` -stats`;
      
      // Add verbose mode if enabled
      if (this.verbose) {
        command += ` -v`;
      }
      
      return command;
    } catch (error) {
      console.error('Error generating template command:', error.message);
      
      // Return a fallback command
      return `"${this.nucleiPath}" -u "${target}" -t "technologies" -j -o "${outputFile}"`;
    }
  }
}

module.exports = NucleiTemplateManager;
