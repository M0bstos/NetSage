require('dotenv').config();
const { query, pool } = require('../db');
const groqService = require('../services/groqService');

/**
 * Generate cybersecurity reports for scan results without reports
 * - Retrieves scan results without report text
 * - Generates report via Groq LLM
 * - Saves report back to database
 * @param {string} [requestId] - Optional specific request ID to generate reports for
 */
async function generateReports(requestId = null) {
  const client = await pool.connect();
  
  try {
    // Begin transaction
    await client.query('BEGIN');
    
    // Find scan results without reports
    let pendingReportsQuery;
    let queryParams = [];
    
    if (requestId) {
      // If specific requestId is provided, only process that one
      pendingReportsQuery = `
        SELECT 
          sr.id as result_id,
          sr.request_id,
          json_build_object(
            'target', sr.target,
            'port', sr.port,
            'service', sr.service,
            'product', sr.product,
            'version', sr.version,
            'protocol', sr.protocol,
            'state', sr.state,
            'banner', sr.banner
          ) as scan_data,
          sr.http_security,
          sr.vulnerabilities,
          sr.vulnerability_summary
        FROM scan_results sr
        JOIN scan_requests sq ON sr.request_id = sq.id
        WHERE sq.status = 'completed' 
          AND (sr.report IS NULL OR sr.report = '')
          AND sr.request_id = $1
      `;
      queryParams.push(requestId);
    } else {
      // Otherwise, find all scan results without reports
      pendingReportsQuery = `
        SELECT 
          sr.id as result_id,
          sr.request_id,
          json_build_object(
            'target', sr.target,
            'port', sr.port,
            'service', sr.service,
            'product', sr.product,
            'version', sr.version,
            'protocol', sr.protocol,
            'state', sr.state,
            'banner', sr.banner
          ) as scan_data,
          sr.http_security,
          sr.vulnerabilities,
          sr.vulnerability_summary
        FROM scan_results sr
        JOIN scan_requests sq ON sr.request_id = sq.id
        WHERE sq.status = 'completed' 
          AND (sr.report IS NULL OR sr.report = '')
      `;
    }
    
    const pendingReportsResult = await client.query(pendingReportsQuery, queryParams);
    console.log(`Found ${pendingReportsResult.rows.length} scan results needing reports`);
    
    if (pendingReportsResult.rows.length === 0) {
      const message = requestId 
        ? `No reports to generate for request ID: ${requestId}`
        : 'No new reports to generate';
      console.log(message);
      return;
    }
    
    // Process each pending report
    for (const row of pendingReportsResult.rows) {
      const { result_id, request_id, scan_data } = row;
      console.log(`Generating report for scan result ID: ${result_id}, request ID: ${request_id}`);
      
      try {
        // Convert scan_data to array if it's not already (since we changed the query)
        const scanDataArray = Array.isArray(scan_data) ? scan_data : [scan_data];
        
        // Parse vulnerabilities if they exist
        let vulnerabilities = [];
        if (row.vulnerabilities) {
          try {
            vulnerabilities = typeof row.vulnerabilities === 'string' 
              ? JSON.parse(row.vulnerabilities) 
              : row.vulnerabilities;
          } catch (parseError) {
            console.error('Error parsing vulnerabilities:', parseError);
          }
        }
        
        // Parse HTTP security if it exists
        let httpSecurity = null;
        if (row.http_security) {
          try {
            httpSecurity = typeof row.http_security === 'string'
              ? JSON.parse(row.http_security)
              : row.http_security;
          } catch (parseError) {
            console.error('Error parsing HTTP security:', parseError);
          }
        }
        
        // Call Groq API to generate report with enhanced data
        const report = await groqService.generateReport(scanDataArray, vulnerabilities, httpSecurity);
        
        // Update scan_results with the generated report
        await client.query(
          'UPDATE scan_results SET report = $1 WHERE id = $2',
          [report, result_id]
        );
        
        console.log(`Successfully generated report for scan result ID: ${result_id}`);
      } catch (error) {
        console.error(`Error generating report for scan result ID: ${result_id}:`, error);
        // Continue to the next entry if one fails
      }
    }
    
    // Commit transaction
    await client.query('COMMIT');
    console.log('All reports generated successfully');
    
  } catch (error) {
    // Rollback transaction on error
    await client.query('ROLLBACK');
    console.error('Error in generateReports:', error);
    throw error;
  } finally {
    // Release client back to pool
    client.release();
  }
}

// Execute the function if script is run directly
if (require.main === module) {
  generateReports()
    .then(() => {
      console.log('Report generation complete');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Report generation failed:', error);
      process.exit(1);
    });
}

module.exports = { generateReports };
