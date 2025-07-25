const { query } = require('../db');
const { v4: uuidv4 } = require('uuid');
const stateMachine = require('../services/stateMachine');
const fetch = require('node-fetch');

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
      
      // Insert into scan_requests table with initial state
      const result = await query(
        'INSERT INTO scan_requests (website_url, status) VALUES ($1, $2) RETURNING id',
        [website_url, stateMachine.STATES.PENDING]
      );
      
      const requestId = result.rows[0].id;
      
      console.log(`Scan request created with ID: ${requestId} for URL: ${website_url}`);
      
      // Trigger N8N workflow asynchronously (this can be moved to a dedicated service)
      try {
        // Update state to scanning before triggering the scan
        await stateMachine.changeState(requestId, stateMachine.STATES.SCANNING);
        
        // This would be the actual call to your n8n webhook
        // Update with the proper n8n webhook URL
        const n8nUrl = process.env.N8N_WEBHOOK_URL;
        if (n8nUrl) {
          const n8nResponse = await fetch(n8nUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ requestId, website_url })
          });
          
          if (!n8nResponse.ok) {
            throw new Error(`n8n webhook returned ${n8nResponse.status}`);
          }
          
          console.log(`N8N workflow triggered successfully for request ${requestId}`);
        } else {
          console.log(`[DEV] N8N webhook not configured, would trigger workflow for ${requestId}`);
        }
      } catch (triggerError) {
        console.error(`Error triggering n8n workflow for request ${requestId}:`, triggerError);
        // Set state to failed on error
        await stateMachine.changeState(requestId, stateMachine.STATES.FAILED);
      }
      
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
      
      // Get current state from state machine
      let status;
      try {
        status = await stateMachine.getCurrentState(requestId);
      } catch (stateError) {
        return res.status(404).json({ error: 'Scan request not found' });
      }
      
      // Return appropriate response based on status
      const isTerminalState = [
        stateMachine.STATES.COMPLETED, 
        stateMachine.STATES.FAILED
      ].includes(status);
      
      // For non-terminal states, return current status and message
      if (!isTerminalState) {
        let message;
        switch(status) {
          case stateMachine.STATES.PENDING:
            message = 'Scan is queued and waiting to start';
            break;
          case stateMachine.STATES.SCANNING:
            message = 'Scan is currently in progress';
            break;
          case stateMachine.STATES.PROCESSING:
            message = 'Scan data is being processed';
            break;
          case stateMachine.STATES.GENERATING_REPORT:
            message = 'Cybersecurity report is being generated';
            break;
          default:
            message = 'Scan is in progress';
        }
        
        return res.json({
          success: true,
          status,
          message,
          requestId
        });
      }
      
      // For failed state
      if (status === stateMachine.STATES.FAILED) {
        return res.json({
          success: false,
          status,
          message: 'Scan failed to complete',
          requestId
        });
      }
      
      // For completed state, fetch the scan results and report
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
          message: 'Scan is complete but no results found',
          requestId
        });
      }
      
      res.json({
        success: true,
        status,
        results: resultsResult.rows,
        requestId
      });
      
    } catch (error) {
      console.error('Error fetching scan report:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}

module.exports = new ScanController();
