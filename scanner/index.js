/**
 * NetSage Website Scanner
 * 
 * Express server for webhook endpoints to receive scan requests and trigger scanning
 */

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const Scanner = require('./lib/scanner');

// Load environment variables
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || 'localhost';
const CALLBACK_URL = process.env.CALLBACK_URL || 'http://localhost:3000/api/webhooks/scan-result';

// Initialize Express app
const app = express();

// Configure CORS with specific options
const corsOptions = {
  origin: '*', // Allow all origins
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};
app.use(cors(corsOptions)); // Enable CORS with options

app.use(bodyParser.json());

// Create a map to store active scans
const activeScans = new Map();

/**
 * Format scan results to match the expected format for the backend
 * 
 * @param {string} requestId - The UUID of the scan request
 * @param {object} scanResults - The raw scan results from the scanner
 * @returns {object} - Formatted results for the backend
 */
function formatResultsForBackend(requestId, scanResults) {
  const formattedResults = {
    request_id: requestId,
    scan_data: []
  };

  // Extract target hostname
  const target = scanResults.target.hostname;

  // Add port information
  if (scanResults.ports && scanResults.ports.length > 0) {
    scanResults.ports.forEach(port => {
      formattedResults.scan_data.push({
        target: target,
        port: parseInt(port.port),
        service: port.service,
        product: port.service,  // Default to service name if no product specified
        version: port.version || ''
      });
    });
  }

  // If HTTP information is available and no ports were found,
  // add an entry for the HTTP service
  if (scanResults.http && formattedResults.scan_data.length === 0) {
    // Extract port from HTTP URL or use default
    const { port } = scanResults.target;
    const service = scanResults.target.protocol === 'https' ? 'https' : 'http';
    
    formattedResults.scan_data.push({
      target: target,
      port: parseInt(port),
      service: service,
      product: scanResults.http.server !== 'unknown' ? scanResults.http.server : service,
      version: ''
    });
  }

  return formattedResults;
}

/**
 * Send scan results back to the main backend
 * 
 * @param {string} requestId - The UUID of the scan request
 * @param {object} results - The formatted scan results
 */
async function sendResultsToBackend(requestId, results) {
  try {
    console.log(`Sending results for request ${requestId} to ${CALLBACK_URL}`);
    
    const response = await axios.post(CALLBACK_URL, results, {
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (response.status === 200) {
      console.log(`Successfully sent results for request ${requestId}`);
      return true;
    } else {
      console.error(`Failed to send results: ${response.status} ${response.statusText}`);
      return false;
    }
  } catch (error) {
    console.error(`Error sending results to backend: ${error.message}`);
    return false;
  }
}

/**
 * Run a scan for the given target and request ID
 * 
 * @param {string} target - URL or hostname to scan
 * @param {string} requestId - The UUID of the scan request
 */
async function runScan(target, requestId) {
  try {
    console.log(`Starting scan for ${target} with request ID ${requestId}`);
    
    // Create scanner with settings from environment variables
    const scanner = new Scanner({
      timeout: parseInt(process.env.DEFAULT_SCAN_TIMEOUT || '30000'),
      ports: process.env.DEFAULT_PORTS_TO_SCAN || '21,22,25,80,443,3306,8080,8443',
      aggressive: false
    });
    
    // Track the scan
    activeScans.set(requestId, {
      target,
      startTime: Date.now(),
      status: 'scanning'
    });
    
    // Run the scan
    const results = await scanner.scan(target);
    
    // Format results for the backend
    const formattedResults = formatResultsForBackend(requestId, results);
    
    // Update scan status
    activeScans.set(requestId, {
      ...activeScans.get(requestId),
      status: 'sending',
      completionTime: Date.now()
    });
    
    // Send results to backend
    await sendResultsToBackend(requestId, formattedResults);
    
    // Mark as completed
    activeScans.set(requestId, {
      ...activeScans.get(requestId),
      status: 'completed'
    });
    
    console.log(`Scan completed for ${target} with request ID ${requestId}`);
  } catch (error) {
    console.error(`Error scanning ${target}: ${error.message}`);
    
    // Mark as failed
    activeScans.set(requestId, {
      ...activeScans.get(requestId),
      status: 'failed',
      error: error.message
    });
    
    // Send error to backend
    const errorResult = {
      request_id: requestId,
      scan_data: [],
      error: error.message
    };
    
    await sendResultsToBackend(requestId, errorResult);
  }
}

// Routes

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'up',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

/**
 * Test endpoint to check CORS and connectivity
 */
app.get('/test', (req, res) => {
  console.log('Received test request with headers:', req.headers);
  res.json({
    success: true,
    message: 'Test endpoint working correctly',
    cors: 'enabled',
    timestamp: new Date().toISOString()
  });
});

/**
 * Scan request endpoint - receives requests from the main backend
 */
app.post('/scan', async (req, res) => {
  try {
    console.log('Received scan request with headers:', req.headers);
    console.log('Request body:', req.body);
    
    const { website_url, requestId } = req.body;
    
    if (!website_url) {
      console.log('Missing required parameter: website_url');
      return res.status(400).json({
        success: false,
        message: 'Missing required parameter: website_url'
      });
    }
    
    // Use provided requestId or generate a new one
    const scanRequestId = requestId || uuidv4();
    console.log(`Processing scan for ${website_url} with requestId ${scanRequestId}`);
    
    // Respond immediately to the client
    res.json({
      success: true,
      message: 'Scan request received and processing',
      requestId: scanRequestId
    });
    
    // Run scan asynchronously
    runScan(website_url, scanRequestId);
    
  } catch (error) {
    console.error(`Error processing scan request: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

/**
 * Get scan status endpoint
 */
app.get('/status/:requestId', (req, res) => {
  const { requestId } = req.params;
  
  if (activeScans.has(requestId)) {
    const scan = activeScans.get(requestId);
    res.json({
      success: true,
      requestId,
      status: scan.status,
      target: scan.target,
      startTime: scan.startTime,
      completionTime: scan.completionTime
    });
  } else {
    res.status(404).json({
      success: false,
      message: 'Scan not found',
      requestId
    });
  }
});

/**
 * List all active scans endpoint
 */
app.get('/scans', (req, res) => {
  const scans = Array.from(activeScans.entries()).map(([id, scan]) => ({
    requestId: id,
    ...scan
  }));
  
  res.json({
    success: true,
    count: scans.length,
    scans
  });
});

// Start the server
app.listen(PORT, HOST, () => {
  console.log(`NetSage Scanner server listening at http://${HOST}:${PORT}`);
  console.log(`Callback URL for results: ${CALLBACK_URL}`);
});
