/**
 * Scheduler Service for automated tasks
 * Manages scheduled jobs for the application
 */
const schedule = require('node-schedule');
const stateMachine = require('./stateMachine');
const { processRawData } = require('../processors/cleanAndProcessData');
const { generateReports } = require('../processors/generateReport');

class SchedulerService {
  constructor() {
    this.jobs = {};
  }

  /**
   * Initialize the scheduler service
   */
  initialize() {
    // Only keep the stuck requests job to ensure nothing stays in a broken state
    this.jobs.stuckRequests = schedule.scheduleJob('*/30 * * * *', async () => {
      console.log('Running scheduled job: Process stuck requests');
      try {
        const processedIds = await stateMachine.processStuckRequests();
        console.log(`Processed ${processedIds.length} stuck requests`);
      } catch (error) {
        console.error('Error in stuck requests job:', error);
      }
    });

    // Remove the periodic polling jobs - we'll only process requests directly when they come in

    console.log('Scheduler service initialized - using event-based processing');
  }

  /**
   * Schedule a one-time job for a specific task
   * @param {string} jobName - Name of the job
   * @param {Date} date - When to run the job
   * @param {Function} task - The task function to execute
   */
  scheduleOneTime(jobName, date, task) {
    this.jobs[jobName] = schedule.scheduleJob(date, async () => {
      console.log(`Running one-time job: ${jobName}`);
      try {
        await task();
      } catch (error) {
        console.error(`Error in one-time job ${jobName}:`, error);
      }
      
      // Remove the job after completion
      delete this.jobs[jobName];
    });
    
    console.log(`One-time job ${jobName} scheduled for ${date}`);
  }

  /**
   * Cancel a scheduled job
   * @param {string} jobName - Name of the job to cancel
   * @returns {boolean} - Whether the job was cancelled
   */
  cancelJob(jobName) {
    if (this.jobs[jobName]) {
      this.jobs[jobName].cancel();
      delete this.jobs[jobName];
      console.log(`Job ${jobName} cancelled`);
      return true;
    }
    
    return false;
  }

  /**
   * Process raw data for a specific request
   * @param {string} requestId - UUID of the request to process
   * @returns {Promise<boolean>} - Success status
   */
  async processRequestData(requestId) {
    try {
      console.log(`Processing data for request ${requestId}`);
      const { cleanAndProcessData } = require('../processors/cleanAndProcessData');
      
      // Call cleanAndProcessData with a filter for this specific request
      await cleanAndProcessData(requestId);
      return true;
    } catch (error) {
      console.error(`Error processing data for request ${requestId}:`, error);
      return false;
    }
  }

  /**
   * Generate report for a specific request
   * @param {string} requestId - UUID of the request to generate report for
   * @returns {Promise<boolean>} - Success status
   */
  async generateRequestReport(requestId) {
    try {
      console.log(`Generating report for request ${requestId}`);
      const { generateReports } = require('../processors/generateReport');
      
      // Call generateReports with a filter for this specific request
      await generateReports(requestId);
      return true;
    } catch (error) {
      console.error(`Error generating report for request ${requestId}:`, error);
      return false;
    }
  }
}

module.exports = new SchedulerService();
