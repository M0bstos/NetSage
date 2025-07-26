const { query } = require('../db');
const { runProcessor } = require('../processors/processor');
const stateMachine = require('../services/stateMachine');
const webSocketService = require('../services/webSocketService');

/**
 * Controller for handling webhook endpoints
 */
class WebhookController {
  constructor() {
    // Bind methods to ensure 'this' context is preserved
    this.handleScanResult = this.handleScanResult.bind(this);
    this.handleProcessTrigger = this.handleProcessTrigger.bind(this);
    this._processData = this._processData.bind(this);
  }
  
  /**
   * Handle scan result webhook
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async handleScanResult(req, res) {
    try {
      // Validate request
      if (!req.body || !req.body.request_id) {
        return res.status(400).json({ 
          error: 'Invalid request body, request_id is required' 
        });
      }
      
      const { request_id } = req.body;
      
      // Verify that the request_id exists in scan_requests
      const requestCheck = await query(
        'SELECT id FROM scan_requests WHERE id = $1',
        [request_id]
      );
      
      if (requestCheck.rows.length === 0) {
        return res.status(404).json({ 
          error: 'Scan request not found' 
        });
      }
      
      try {
        // Update state to processing
        await stateMachine.changeState(request_id, stateMachine.STATES.PROCESSING);
      } catch (stateError) {
        console.error(`Error updating state for request ${request_id}:`, stateError);
        // Continue processing even if state update fails
      }
      
      // Insert raw scan data
      await query(
        'INSERT INTO raw_scan_data (request_id, raw_json) VALUES ($1, $2)',
        [request_id, req.body]
      );
      
      console.log(`Received scan results for request ID: ${request_id}`);
      
      // Trigger processor to process this data immediately
      // We now process data automatically as part of the workflow
      try {
        // Schedule immediate processing (will happen in the background)
        const processorResult = await this._processData(request_id);
        console.log(`Processing scheduled for request ${request_id}`);
      } catch (processorError) {
        console.error(`Error scheduling processing for request ${request_id}:`, processorError);
      }
      
      res.status(200).json({ 
        success: true, 
        message: 'Scan results received and saved' 
      });
      
    } catch (error) {
      console.error('Error processing webhook:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  /**
   * Handle process trigger webhook
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async handleProcessTrigger(req, res) {
    try {
      console.log('Processing trigger received from webhook');
      
      // Get specific request ID if provided
      const { request_id } = req.body;
      
      // Run the processor
      let result;
      if (request_id) {
        // Process specific request
        result = await this._processData(request_id);
        
        if (!result) {
          return res.status(404).json({
            success: false,
            message: `Request ID ${request_id} not found or already processed`
          });
        }
      } else {
        // Process all pending requests
        result = await runProcessor();
      }
      
      if (result.success) {
        res.status(200).json({ 
          success: true, 
          message: 'Data processing completed successfully' 
        });
      } else {
        res.status(500).json({ 
          success: false, 
          message: 'Data processing failed', 
          error: result.error.message 
        });
      }
    } catch (error) {
      console.error('Error handling process trigger:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
  
  /**
   * Process data for a specific request
   * @param {string} requestId - UUID of the request to process
   * @returns {Promise<Object>} - Processing result
   * @private
   */
  async _processData(requestId) {
    try {
      // Check if raw data exists
      const rawDataCheck = await query(
        'SELECT id FROM raw_scan_data WHERE request_id = $1',
        [requestId]
      );
      
      if (rawDataCheck.rows.length === 0) {
        console.log(`No raw data found for request ${requestId}`);
        return null;
      }
      
      // Run processor on this specific request
      const result = await runProcessor(requestId);
      
      // Update state based on processing result
      if (result.success) {
        try {
          await stateMachine.changeState(requestId, stateMachine.STATES.GENERATING_REPORT);
        } catch (stateError) {
          console.error(`Error updating state for request ${requestId}:`, stateError);
        }
      } else {
        try {
          await stateMachine.changeState(requestId, stateMachine.STATES.FAILED);
        } catch (stateError) {
          console.error(`Error updating state for request ${requestId}:`, stateError);
        }
      }
      
      return result;
    } catch (error) {
      console.error(`Error processing data for request ${requestId}:`, error);
      
      // Set state to failed
      try {
        await stateMachine.changeState(requestId, stateMachine.STATES.FAILED);
      } catch (stateError) {
        console.error(`Error updating state for request ${requestId}:`, stateError);
      }
      
      return {
        success: false,
        error
      };
    }
  }
}

module.exports = new WebhookController();
