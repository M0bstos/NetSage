require('dotenv').config();
// Import node-fetch properly depending on Node.js version
let fetch;
try {
  // Try using native fetch (Node.js 17.5+)
  fetch = global.fetch;
  if (!fetch) {
    // For older Node.js versions, use node-fetch package
    fetch = require('node-fetch');
  }
} catch (err) {
  // Fallback to require node-fetch
  fetch = require('node-fetch');
}

/**
 * Service class for interacting with Groq API
 */
class GroqService {
  constructor() {
    this.apiKey = process.env.GROQ_API_KEY;
    this.baseUrl = 'https://api.groq.com/openai/v1';
    this.model = 'llama3-70b-8192';
    
    if (!this.apiKey) {
      console.warn('Warning: GROQ_API_KEY is not set in the environment variables');
    }
  }

  /**
   * Generate a report using the Groq API
   * @param {Object} scanData - Scan data to include in the prompt
   * @param {Array} vulnerabilities - Optional vulnerabilities data
   * @param {Object} httpSecurity - Optional HTTP security headers data
   * @returns {Promise<string>} - The generated report text
   */
  async generateReport(scanData, vulnerabilities = [], httpSecurity = null) {
    try {
      const prompt = this._buildPrompt(scanData, vulnerabilities, httpSecurity);
      const response = await this._callGroqApi(prompt);
      return response;
    } catch (error) {
      console.error('Error generating report with Groq:', error);
      throw new Error('Failed to generate report with Groq API');
    }
  }

  /**
   * Build a prompt for the LLM based on scan data
   * @param {Array} scanData - Array of scan results
   * @param {Array} vulnerabilities - Array of vulnerability findings
   * @param {Object} httpSecurity - HTTP security headers information
   * @returns {string} - The formatted prompt
   */
  _buildPrompt(scanData, vulnerabilities = [], httpSecurity = null) {
    // Create a detailed and structured prompt for the LLM
    let prompt = `Generate a comprehensive cybersecurity report for the following scan results. 
The report should:
1. Summarize the detected services and their versions
2. Analyze the detected vulnerabilities
3. Review HTTP security headers configuration
4. Provide recommendations for securing these services and addressing vulnerabilities
5. Rate the overall security posture on a scale of 1-10
6. Format the report in markdown with clear sections

Here are the scan results:
`;

    // Add scan data to prompt
    scanData.forEach(item => {
      prompt += `\n- Target: ${item.target || 'Unknown'}`;
      prompt += `\n  Port: ${item.port || 'Unknown'}`;
      prompt += `\n  Service: ${item.service || 'Unknown'}`;
      prompt += `\n  Product: ${item.product || 'Unknown'}`;
      prompt += `\n  Version: ${item.version || 'Unknown'}`;
      if (item.state) prompt += `\n  State: ${item.state}`;
      if (item.protocol) prompt += `\n  Protocol: ${item.protocol}`;
      prompt += '\n';
    });

    // Add vulnerability information if available
    if (vulnerabilities && vulnerabilities.length > 0) {
      prompt += `\nVulnerabilities Found:`;
      vulnerabilities.forEach(vuln => {
        prompt += `\n- Name: ${vuln.name || 'Unknown'}`;
        prompt += `\n  Severity: ${vuln.severity || 'Unknown'}`;
        prompt += `\n  Type: ${vuln.type || 'Unknown'}`;
        if (vuln.description) prompt += `\n  Description: ${vuln.description}`;
        if (vuln.references && vuln.references.length) prompt += `\n  References: ${vuln.references.join(', ')}`;
        prompt += '\n';
      });
    }

    // Add HTTP security headers information if available
    if (httpSecurity && httpSecurity.headers) {
      prompt += `\nHTTP Security Headers:`;
      const headers = httpSecurity.headers;
      for (const [key, value] of Object.entries(headers)) {
        if (!key.startsWith('has')) continue;
        const headerName = key.replace('has', '');
        prompt += `\n- ${headerName}: ${value ? 'Present' : 'Missing'}`;
      }
      prompt += '\n';
    }

    prompt += `\nAdditional information: Some services may have default configurations that pose security risks.
Please provide a detailed analysis focusing on practical security improvements.`;

    return prompt;
  }

  /**
   * Call the Groq API with a prompt
   * @param {string} prompt - The prompt to send to the API
   * @returns {Promise<string>} - The generated text response
   */
  async _callGroqApi(prompt) {
    // If no API key is set, or we're in testing mode, return a mock response
    if (!this.apiKey || process.env.SKIP_GROQ_API === 'true') {
      console.log('Using mock Groq response (no API key or in testing mode)');
      return this._getMockResponse();
    }
    
    const url = `${this.baseUrl}/chat/completions`;
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`
      },
      body: JSON.stringify({
        model: this.model,
        messages: [
          { role: 'system', content: 'You are a cybersecurity expert tasked with analyzing scan results and providing actionable security recommendations.' },
          { role: 'user', content: prompt }
        ],
        temperature: 0.7,
        max_tokens: 4000
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Groq API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    return data.choices[0].message.content;
  }
  
  /**
   * Get a mock response for testing
   * @returns {string} - A mock cybersecurity report
   * @private
   */
  _getMockResponse() {
    return `# Cybersecurity Report - Mock Test Response

## Summary of Detected Services
Based on the scan results, the following services were detected:
- Web server on port 80/443 (likely HTTP/HTTPS)
- Additional potential services on various ports

## Security Analysis
The scan detected services that may have security implications:

1. **Open Ports**: Several open ports were detected which increase the attack surface
2. **HTTP Security Headers**: Missing important security headers that help prevent common web attacks
3. **WAF Detection**: A web application firewall was detected, which provides some protection

## Recommendations
1. **Minimize Open Ports**: Close unnecessary ports to reduce attack surface
2. **Implement Security Headers**: Add recommended HTTP security headers
3. **Keep Software Updated**: Ensure all services are running the latest versions
4. **Regular Scanning**: Perform regular security scans to detect new vulnerabilities

## Overall Security Posture
Based on the findings, the security posture is rated as **6/10**. While some security measures are in place, there are several improvements that could significantly enhance the security profile.

*This is a mock report generated for testing purposes.*`;
  }
}

module.exports = new GroqService();
