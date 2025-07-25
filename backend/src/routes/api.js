const express = require('express');
const scanController = require('../controllers/scanController');
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

module.exports = router;
