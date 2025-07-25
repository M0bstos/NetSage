require('dotenv').config();
const { query, pool } = require('../db');
const groqService = require('../services/groqService');

/**
 * Generate cybersecurity reports for scan results without reports
 * - Retrieves scan results without report text
 * - Generates report via Groq LLM
 * - Saves report back to database
 */
async function generateReports() {
  const client = await pool.connect();
  
  try {
    // Begin transaction
    await client.query('BEGIN');
    
    // Find scan results without reports
    // Look for completed scan_requests with scan_results entries that have no report
    const pendingReportsQuery = `
      SELECT 
        sr.id as result_id,
        sr.request_id,
        array_agg(json_build_object(
          'target', sr.target,
          'port', sr.port,
          'service', sr.service,
          'product', sr.product,
          'version', sr.version
        )) as scan_data
      FROM scan_results sr
      JOIN scan_requests sq ON sr.request_id = sq.id
      WHERE sq.status = 'completed' 
        AND (sr.report IS NULL OR sr.report = '')
      GROUP BY sr.request_id, sr.id
    `;
    
    const pendingReportsResult = await client.query(pendingReportsQuery);
    console.log(`Found ${pendingReportsResult.rows.length} scan results needing reports`);
    
    if (pendingReportsResult.rows.length === 0) {
      console.log('No new reports to generate');
      return;
    }
    
    // Process each pending report
    for (const row of pendingReportsResult.rows) {
      const { result_id, request_id, scan_data } = row;
      console.log(`Generating report for scan result ID: ${result_id}, request ID: ${request_id}`);
      
      try {
        // Call Groq API to generate report
        const report = await groqService.generateReport(scan_data);
        
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
