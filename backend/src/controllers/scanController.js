const { query } = require('../config/db');
const { v4: uuidv4 } = require('uuid');

/**
 * Controller for handling scan-related API endpoints
 */
class ScanController {
  /**
   * Create a new scan request
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async createScan(req, res) {
    try {
      const { website_url } = req.body;
      
      if (!website_url) {
        return res.status(400).json({ error: 'Website URL is required' });
      }
      
      // Insert into scan_requests table
      const result = await query(
        'INSERT INTO scan_requests (website_url, status) VALUES ($1, $2) RETURNING id',
        [website_url, 'pending']
      );
      
      const requestId = result.rows[0].id;
      
      // Here you would trigger n8n workflow with the URL
      // This is just a placeholder for the webhook/API call to n8n
      console.log(`Scan request created with ID: ${requestId} for URL: ${website_url}`);
      
      res.status(201).json({ 
        success: true, 
        message: 'Scan request created successfully',
        requestId 
      });
    } catch (error) {
      console.error('Error creating scan request:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Get scan report by request ID
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async getReport(req, res) {
    try {
      const { requestId } = req.params;
      
      // First check scan_requests table for status
      const requestResult = await query(
        'SELECT status FROM scan_requests WHERE id = $1',
        [requestId]
      );
      
      if (requestResult.rows.length === 0) {
        return res.status(404).json({ error: 'Scan request not found' });
      }
      
      const status = requestResult.rows[0].status;
      
      // If status is pending, return only the status
      if (status === 'pending') {
        return res.json({
          success: true,
          status,
          message: 'Scan is still in progress'
        });
      }
      
      // If status is completed, fetch the scan results and report
      const resultsQuery = `
        SELECT 
          sr.target, 
          sr.port, 
          sr.service, 
          sr.product, 
          sr.version, 
          sr.report
        FROM 
          scan_results sr
        WHERE 
          sr.request_id = $1
      `;
      
      const resultsResult = await query(resultsQuery, [requestId]);
      
      if (resultsResult.rows.length === 0) {
        return res.json({
          success: true,
          status,
          message: 'Scan is complete but no results found'
        });
      }
      
      res.json({
        success: true,
        status,
        results: resultsResult.rows
      });
      
    } catch (error) {
      console.error('Error fetching scan report:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}

module.exports = new ScanController();
