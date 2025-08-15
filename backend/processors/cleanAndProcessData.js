require('dotenv').config();
const { query, pool } = require('../db');

/**
 * Clean and process raw scan data
 * - Fetches raw data from raw_scan_data table
 * - Extracts and validates relevant information
 * - Saves processed data to scan_results table
 * - Updates scan request status to 'completed'
 * @param {string} [requestId] - Optional specific request ID to process
 */
async function cleanAndProcessData(requestId = null) {
  const client = await pool.connect();
  
  try {
    // Begin transaction
    await client.query('BEGIN');
    
    // Find raw data to process
    let rawDataQuery;
    let queryParams = [];
    
    if (requestId) {
      // If specific requestId is provided, only process that one
      rawDataQuery = `
        SELECT rd.id, rd.request_id, rd.raw_json
        FROM raw_scan_data rd
        LEFT JOIN scan_results sr ON rd.request_id = sr.request_id
        WHERE sr.id IS NULL AND rd.request_id = $1
      `;
      queryParams.push(requestId);
    } else {
      // Otherwise, find all unprocessed raw data
      rawDataQuery = `
        SELECT rd.id, rd.request_id, rd.raw_json
        FROM raw_scan_data rd
        LEFT JOIN scan_results sr ON rd.request_id = sr.request_id
        WHERE sr.id IS NULL
      `;
    }
    
    const rawDataResult = await client.query(rawDataQuery, queryParams);
    console.log(`Found ${rawDataResult.rows.length} raw scan results to process`);
    
    if (rawDataResult.rows.length === 0) {
      const message = requestId 
        ? `No raw data to process for request ID: ${requestId}`
        : 'No new raw data to process';
      console.log(message);
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
        const extracted = extractScanResults(scanData);
        
        if (!extracted.scanResults || extracted.scanResults.length === 0) {
          console.log(`No scan results extracted from raw data ID: ${id}`);
          continue;
        }
        
        // Begin nested transaction for saving all the data
        await client.query('BEGIN');
        
        try {
          // Insert each scan result into scan_results table
          for (const result of extracted.scanResults) {
            await client.query(
              `INSERT INTO scan_results 
                (request_id, target, port, service, product, version, protocol, state, banner) 
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
              [
                request_id, 
                result.target || null, 
                parseInt(result.port) || null, 
                result.service || null, 
                result.product || null, 
                result.version || null,
                result.protocol || null,
                result.state || null,
                result.banner || null
              ]
            );
          }
          
          // Insert each scan result into scan_results table with all metadata
          for (const result of extracted.scanResults) {
            await client.query(
              `INSERT INTO scan_results 
                (request_id, target, port, service, product, version, protocol, state, banner,
                 http_security, vulnerabilities, vulnerability_summary, scan_metadata, 
                 scan_timestamp, scan_duration) 
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
              [
                request_id, 
                result.target || null, 
                parseInt(result.port) || null, 
                result.service || null, 
                result.product || null, 
                result.version || null,
                result.protocol || null,
                result.state || null,
                result.banner || null,
                extracted.httpSecurity ? JSON.stringify(extracted.httpSecurity) : null,
                extracted.vulnerabilities ? JSON.stringify(extracted.vulnerabilities) : null,
                extracted.vulnerabilitySummary ? JSON.stringify(extracted.vulnerabilitySummary) : null,
                extracted.scanMetadata ? JSON.stringify(extracted.scanMetadata) : null,
                extracted.scanTimestamp ? new Date(extracted.scanTimestamp) : null,
                extracted.scanDuration
              ]
            );
          }
          
          // Update scan request status to completed
          await client.query(
            'UPDATE scan_requests SET status = $1 WHERE id = $2',
            ['completed', request_id]
          );
          
          await client.query('COMMIT');
        } catch (error) {
          await client.query('ROLLBACK');
          console.error(`Error saving processed data for request ${request_id}:`, error);
          throw error;
        }
        
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
    // Handle the new JSON structure with scan_data
    if (rawData && typeof rawData === 'object' && rawData.scan_data && Array.isArray(rawData.scan_data)) {
      const results = [];
      
      // Process each item in the scan_data array
      rawData.scan_data.forEach(item => {
        // Direct target-port-service entries
        if (item.target && (item.port || item.port === 0)) {
          results.push({
            target: item.target,
            port: item.port,
            service: item.service || '',
            product: item.product || '',
            version: item.version || '',
            protocol: item.protocol || '',
            state: item.state || '',
            banner: item.banner || ''
          });
        }
      });
      
      // Return processed results along with metadata
      return {
        scanResults: results,
        httpSecurity: rawData.http_security || null,
        vulnerabilities: rawData.vulnerabilities || [],
        vulnerabilitySummary: rawData.vulnerability_summary || null,
        scanMetadata: rawData.scan_metadata || null,
        scanTimestamp: rawData.scan_timestamp || null,
        scanDuration: rawData.scan_duration_ms || null,
        errors: rawData.errors || []
      };
    }
    
    // Handle if the rawData is an array directly (legacy format)
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
      
      return { scanResults: results };
    }
    
    // If rawData is an object with embedded results (legacy format)
    if (rawData && typeof rawData === 'object') {
      // Check for scan_results array
      if (rawData.scan_results && Array.isArray(rawData.scan_results)) {
        return { scanResults: rawData.scan_results };
      }
      
      // Check for data array
      if (rawData.data && Array.isArray(rawData.data)) {
        return { scanResults: rawData.data };
      }
      
      // Check for output.data
      if (rawData.output && rawData.output.data) {
        return { 
          scanResults: Array.isArray(rawData.output.data) ? rawData.output.data : [rawData.output.data] 
        };
      }
    }
    
    console.warn('Could not extract scan results from raw data, unknown structure');
    return { scanResults: [] };
  } catch (error) {
    console.error('Error extracting scan results:', error);
    return { scanResults: [] };
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
