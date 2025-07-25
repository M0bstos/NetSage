const express = require('express');
const webhookController = require('../controllers/webhookController');
const router = express.Router();

/**
 * POST /webhooks/scan-result
 * Webhook endpoint for n8n to send scan results
 * Saves raw scan data to raw_scan_data table
 */
router.post('/scan-result', webhookController.handleScanResult);

/**
 * POST /webhooks/process-trigger
 * Endpoint for n8n to trigger data processing
 * Useful for scheduling or manual triggering
 */
router.post('/process-trigger', webhookController.handleProcessTrigger);

module.exports = router;
