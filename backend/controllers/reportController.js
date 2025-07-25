const { generateReports } = require('../processors/generateReport');
const { query } = require('../db');
const stateMachine = require('../services/stateMachine');

/**
 * Controller for handling report-related operations
 */
class ReportController {
  /**
   * Generate reports for scan results without reports
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   */
  async generateReports(req, res) {
    try {
      console.log('Manual report generation triggered');
      
      // Get specific request ID if provided
      const { requestId } = req.body;
      
      if (requestId) {
        await this._generateReportForRequest(requestId);
        res.status(200).json({ 
          success: true, 
          message: `Report generation completed for request ${requestId}` 
        });
      } else {
        // Run report generation for all applicable scan results
        await generateReports();
        
        res.status(200).json({ 
          success: true, 
          message: 'Report generation completed successfully' 
        });
      }
    } catch (error) {
      console.error('Error generating reports:', error);
      res.status(500).json({ 
        error: 'Failed to generate reports',
        message: error.message
      });
    }
  }
  
  /**
   * Generate report for a specific request
   * @param {string} requestId - UUID of the request to generate report for
   * @returns {Promise<boolean>} - Success status
   * @private
   */
  async _generateReportForRequest(requestId) {
    try {
      // Check if request exists
      const requestCheck = await query(
        'SELECT id FROM scan_requests WHERE id = $1',
        [requestId]
      );
      
      if (requestCheck.rows.length === 0) {
        console.error(`Request ${requestId} not found`);
        return false;
      }
      
      // Update state to generating report
      try {
        await stateMachine.changeState(requestId, stateMachine.STATES.GENERATING_REPORT);
      } catch (stateError) {
        console.error(`Error updating state for request ${requestId}:`, stateError);
        // Continue even if state update fails
      }
      
      // Generate report for this specific request
      const result = await generateReports(requestId);
      
      // Update state to completed
      if (result.success) {
        try {
          await stateMachine.changeState(requestId, stateMachine.STATES.COMPLETED);
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
      
      return result.success;
    } catch (error) {
      console.error(`Error generating report for request ${requestId}:`, error);
      
      // Set state to failed
      try {
        await stateMachine.changeState(requestId, stateMachine.STATES.FAILED);
      } catch (stateError) {
        console.error(`Error updating state for request ${requestId}:`, stateError);
      }
      
      return false;
    }
  }
}

module.exports = new ReportController();
