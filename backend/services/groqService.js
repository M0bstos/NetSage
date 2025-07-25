const fetch = require('node-fetch');
require('dotenv').config();

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
   * @returns {Promise<string>} - The generated report text
   */
  async generateReport(scanData) {
    try {
      const prompt = this._buildPrompt(scanData);
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
   * @returns {string} - The formatted prompt
   */
  _buildPrompt(scanData) {
    // Create a detailed and structured prompt for the LLM
    let prompt = `Generate a comprehensive cybersecurity report for the following scan results. 
The report should:
1. Summarize the detected services and their versions
2. Identify potential security vulnerabilities based on the services and versions detected
3. Provide recommendations for securing these services
4. Rate the overall security posture on a scale of 1-10
5. Format the report in markdown with clear sections

Here are the scan results:
`;

    // Add scan data to prompt
    scanData.forEach(item => {
      prompt += `\n- Target: ${item.target || 'Unknown'}`;
      prompt += `\n  Port: ${item.port || 'Unknown'}`;
      prompt += `\n  Service: ${item.service || 'Unknown'}`;
      prompt += `\n  Product: ${item.product || 'Unknown'}`;
      prompt += `\n  Version: ${item.version || 'Unknown'}\n`;
    });

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
}

module.exports = new GroqService();
