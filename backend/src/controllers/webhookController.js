const { query } = require('../config/db');
const { runProcessor } = require('../processors/processor');

/**
 * Controller for handling webhook endpoints
 */
class WebhookController {
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
      
      // Insert raw scan data
      await query(
        'INSERT INTO raw_scan_data (request_id, raw_json) VALUES ($1, $2)',
        [request_id, req.body]
      );
      
      console.log(`Received scan results for request ID: ${request_id}`);
      
      // Optional: Trigger processor to process this data immediately
      // Uncomment if you want immediate processing
      // await runProcessor();
      
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
      
      // Run the processor
      const result = await runProcessor();
      
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
}

module.exports = new WebhookController();
