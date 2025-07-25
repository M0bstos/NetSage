require('dotenv').config();
const { query, pool } = require('../db');

/**
 * Clean and process raw scan data
 * - Fetches raw data from raw_scan_data table
 * - Extracts and validates relevant information
 * - Saves processed data to scan_results table
 * - Updates scan request status to 'completed'
 */
async function cleanAndProcessData() {
  const client = await pool.connect();
  
  try {
    // Begin transaction
    await client.query('BEGIN');
    
    // Find unprocessed raw data
    // Look for raw_scan_data entries where there's no corresponding scan_results entry
    const rawDataQuery = `
      SELECT rd.id, rd.request_id, rd.raw_json
      FROM raw_scan_data rd
      LEFT JOIN scan_results sr ON rd.request_id = sr.request_id
      WHERE sr.id IS NULL
    `;
    
    const rawDataResult = await client.query(rawDataQuery);
    console.log(`Found ${rawDataResult.rows.length} raw scan results to process`);
    
    if (rawDataResult.rows.length === 0) {
      console.log('No new raw data to process');
      return;
    }
    
    // Process each raw data entry
    for (const row of rawDataResult.rows) {
      const { id, request_id, raw_json } = row;
      console.log(`Processing raw data ID: ${id} for request ID: ${request_id}`);
      
      try {
        // Parse raw JSON if it's a string
        const scanData = typeof raw_json === 'string' ? JSON.parse(raw_json) : raw_json;
        
        // Extract data from the raw JSON
        const extractedResults = extractScanResults(scanData);
        
        if (!extractedResults || extractedResults.length === 0) {
          console.log(`No scan results extracted from raw data ID: ${id}`);
          continue;
        }
        
        // Insert each extracted result into scan_results table
        for (const result of extractedResults) {
          await client.query(
            `INSERT INTO scan_results 
              (request_id, target, port, service, product, version) 
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [
              request_id, 
              result.target || null, 
              parseInt(result.port) || null, 
              result.service || null, 
              result.product || null, 
              result.version || null
            ]
          );
        }
        
        // Update scan request status to 'completed'
        await client.query(
          'UPDATE scan_requests SET status = $1 WHERE id = $2',
          ['completed', request_id]
        );
        
        console.log(`Successfully processed raw data ID: ${id} for request ID: ${request_id}`);
      } catch (error) {
        console.error(`Error processing raw data ID: ${id}:`, error);
        // Continue to the next entry if one fails
      }
    }
    
    // Commit transaction
    await client.query('COMMIT');
    console.log('All raw data processed successfully');
    
  } catch (error) {
    // Rollback transaction on error
    await client.query('ROLLBACK');
    console.error('Error in cleanAndProcessData:', error);
    throw error;
  } finally {
    // Release client back to pool
    client.release();
  }
}

/**
 * Extract scan results from raw JSON data based on the sample output format
 * @param {Object|Array} rawData - Raw JSON data from n8n workflow
 * @returns {Array} - Extracted scan results
 */
function extractScanResults(rawData) {
  try {
    // Handle if the rawData is an array directly (as in the provided sample)
    if (Array.isArray(rawData)) {
      const results = [];
      
      // Process each item in the array
      rawData.forEach(item => {
        // Direct target-port-service entries
        if (item.target && (item.port || item.port === 0) && item.service) {
          results.push({
            target: item.target,
            port: item.port,
            service: item.service,
            product: item.product || '',
            version: item.version || ''
          });
        }
      });
      
      return results;
    }
    
    // If rawData is an object with embedded results
    if (rawData && typeof rawData === 'object') {
      // Check for scan_results array
      if (rawData.scan_results && Array.isArray(rawData.scan_results)) {
        return rawData.scan_results;
      }
      
      // Check for data array
      if (rawData.data && Array.isArray(rawData.data)) {
        return rawData.data;
      }
      
      // Check for output.data
      if (rawData.output && rawData.output.data) {
        return Array.isArray(rawData.output.data) ? rawData.output.data : [rawData.output.data];
      }
    }
    
    console.warn('Could not extract scan results from raw data, unknown structure');
    return [];
  } catch (error) {
    console.error('Error extracting scan results:', error);
    return [];
  }
}

// Execute the function if script is run directly
if (require.main === module) {
  cleanAndProcessData()
    .then(() => {
      console.log('Data processing complete');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Data processing failed:', error);
      process.exit(1);
    });
}

module.exports = { cleanAndProcessData };
