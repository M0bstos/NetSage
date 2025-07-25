require('dotenv').config();
const { cleanAndProcessData } = require('./cleanAndProcessData');
const { generateReports } = require('./generateReport');

/**
 * Processor script to handle data processing workflow
 * 
 * This script can be:
 * 1. Run manually: node processor.js
 * 2. Scheduled via cron job
 * 3. Triggered by webhook completion
 */
async function runProcessor() {
  try {
    console.log('Starting data processing workflow...');
    
    // Step 1: Process raw scan data
    console.log('Step 1: Processing raw scan data...');
    await cleanAndProcessData();
    
    // Step 2: Generate reports for processed data
    console.log('Step 2: Generating reports for processed data...');
    await generateReports();
    
    console.log('Data processing workflow completed successfully');
    return { success: true };
  } catch (error) {
    console.error('Data processing workflow failed:', error);
    return { success: false, error };
  }
}

// Execute the function if script is run directly
if (require.main === module) {
  runProcessor()
    .then((result) => {
      if (result.success) {
        console.log('Processor completed successfully');
        process.exit(0);
      } else {
        console.error('Processor failed:', result.error);
        process.exit(1);
      }
    })
    .catch((error) => {
      console.error('Unexpected error in processor:', error);
      process.exit(1);
    });
}

module.exports = { runProcessor };
