const express = require('express');
const scanController = require('../controllers/scanController');
const reportController = require('../controllers/reportController');
const stateMachine = require('../services/stateMachine');
const router = express.Router();

/**
 * POST /api/scan
 * Receives website URL from frontend
 * Saves to scan_requests table with status 'pending'
 * Returns request ID to frontend
 */
router.post('/scan', scanController.createScan);

/**
 * GET /api/report/:requestId
 * Frontend queries this endpoint with request ID
 * Returns scan result and generated report if completed
 * Otherwise, returns current status
 */
router.get('/report/:requestId', scanController.getReport);

/**
 * GET /api/scan-status/:requestId
 * Get the current status of a scan request
 * Used for clients that don't support WebSockets
 */
router.get('/scan-status/:requestId', async (req, res) => {
  try {
    const { requestId } = req.params;
    
    // Get current state from state machine
    let status;
    try {
      status = await stateMachine.getCurrentState(requestId);
    } catch (stateError) {
      return res.status(404).json({ error: 'Scan request not found' });
    }
    
    return res.json({
      success: true,
      requestId,
      status
    });
  } catch (error) {
    console.error('Error getting scan status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * POST /api/generate-reports
 * Manually trigger report generation for scan results without reports
 */
router.post('/generate-reports', reportController.generateReports);

/**
 * POST /api/retry-scan/:requestId
 * Retry a failed scan
 */
router.post('/retry-scan/:requestId', async (req, res) => {
  try {
    const { requestId } = req.params;
    
    // Get current state
    let currentState;
    try {
      currentState = await stateMachine.getCurrentState(requestId);
    } catch (stateError) {
      return res.status(404).json({ error: 'Scan request not found' });
    }
    
    // Only failed scans can be retried
    if (currentState !== stateMachine.STATES.FAILED) {
      return res.status(400).json({
        error: 'Only failed scans can be retried',
        currentState
      });
    }
    
    // Reset state to pending
    await stateMachine.changeState(requestId, stateMachine.STATES.PENDING);
    
    // Trigger scan again (implementation would depend on how scans are initiated)
    // For now, we'll just respond with success
    res.json({
      success: true,
      message: 'Scan retry initiated',
      requestId
    });
  } catch (error) {
    console.error('Error retrying scan:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
