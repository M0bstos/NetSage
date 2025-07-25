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
    // Schedule job to process stuck requests every 10 minutes
    this.jobs.stuckRequests = schedule.scheduleJob('*/10 * * * *', async () => {
      console.log('Running scheduled job: Process stuck requests');
      try {
        const processedIds = await stateMachine.processStuckRequests();
        console.log(`Processed ${processedIds.length} stuck requests`);
      } catch (error) {
        console.error('Error in stuck requests job:', error);
      }
    });

    // Schedule job to process raw data every 5 minutes
    this.jobs.processRawData = schedule.scheduleJob('*/5 * * * *', async () => {
      console.log('Running scheduled job: Process raw data');
      try {
        const { cleanAndProcessData } = require('../processors/cleanAndProcessData');
        await cleanAndProcessData();
      } catch (error) {
        console.error('Error in process raw data job:', error);
      }
    });

    // Schedule job to generate reports every 5 minutes
    this.jobs.generateReports = schedule.scheduleJob('*/5 * * * *', async () => {
      console.log('Running scheduled job: Generate reports');
      try {
        await generateReports();
      } catch (error) {
        console.error('Error in generate reports job:', error);
      }
    });

    console.log('Scheduler service initialized');
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
}

module.exports = new SchedulerService();
