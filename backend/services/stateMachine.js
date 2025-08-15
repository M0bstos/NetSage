/**
 * State Machine Service for managing scan workflow states
 * Implements a state pattern to handle transitions and actions
 */
const { query } = require('../db');
const { EventEmitter } = require('events');

// Define valid states
const STATES = {
  PENDING: 'pending',
  SCANNING: 'scanning',
  PROCESSING: 'processing', 
  GENERATING_REPORT: 'generating_report',
  COMPLETED: 'completed',
  FAILED: 'failed'
};

// Define valid transitions
const VALID_TRANSITIONS = {
  [STATES.PENDING]: [STATES.SCANNING, STATES.FAILED],
  [STATES.SCANNING]: [STATES.PROCESSING, STATES.FAILED],
  [STATES.PROCESSING]: [STATES.GENERATING_REPORT, STATES.FAILED],
  [STATES.GENERATING_REPORT]: [STATES.COMPLETED, STATES.FAILED],
  [STATES.COMPLETED]: [],
  [STATES.FAILED]: [STATES.PENDING] // Allow retrying from failed state
};

class StateMachine extends EventEmitter {
  constructor() {
    super();
    this.STATES = STATES;
  }

  /**
   * Get the current state of a scan request
   * @param {string} requestId - UUID of the scan request
   * @returns {Promise<string>} - Current state
   */
  async getCurrentState(requestId) {
    try {
      const result = await query(
        'SELECT status FROM scan_requests WHERE id = $1',
        [requestId]
      );
      
      if (result.rows.length === 0) {
        throw new Error(`Scan request ${requestId} not found`);
      }
      
      return result.rows[0].status;
    } catch (error) {
      console.error(`Error getting state for request ${requestId}:`, error);
      throw error;
    }
  }

  /**
   * Change state of a scan request
   * @param {string} requestId - UUID of the scan request
   * @param {string} newState - State to transition to
   * @param {boolean} force - Whether to force the transition even if not valid
   * @returns {Promise<boolean>} - Success status
   */
  async changeState(requestId, newState, force = false) {
    try {
      // Get current state
      const currentState = await this.getCurrentState(requestId);
      
      // Validate the transition (unless forced)
      if (!force && !this._isValidTransition(currentState, newState)) {
        throw new Error(`Invalid state transition from ${currentState} to ${newState}`);
      }
      
      // Don't update if state is the same
      if (currentState === newState) {
        console.log(`State for ${requestId} is already ${newState}, no update needed`);
        return true;
      }
      
      // Log if forcing an invalid transition
      if (force && !this._isValidTransition(currentState, newState)) {
        console.log(`Forcing invalid state transition from ${currentState} to ${newState} for request ${requestId}`);
      }
      
      // Update state in database
      await query(
        'UPDATE scan_requests SET status = $1 WHERE id = $2',
        [newState, requestId]
      );
      
      // Emit state change event
      this.emit('stateChanged', {
        requestId,
        prevState: currentState,
        newState,
        timestamp: new Date()
      });
      
      console.log(`State changed for request ${requestId}: ${currentState} -> ${newState}`);
      return true;
    } catch (error) {
      console.error(`Error changing state for request ${requestId}:`, error);
      throw error;
    }
  }

  /**
   * Check if a state transition is valid
   * @param {string} currentState - Current state
   * @param {string} newState - Proposed new state
   * @returns {boolean} - Whether the transition is valid
   * @private
   */
  _isValidTransition(currentState, newState) {
    // Check if current state exists in transition map
    if (!VALID_TRANSITIONS[currentState]) {
      return false;
    }
    
    // Check if new state is a valid transition from current state
    return VALID_TRANSITIONS[currentState].includes(newState);
  }

  /**
   * Find and process scan requests that are stuck in a non-terminal state
   * @returns {Promise<Array>} - Array of processed request IDs
   */
  async processStuckRequests() {
    try {
      // Find requests that have been in non-terminal states for too long
      // For simplicity, we'll just look at pending requests older than 15 minutes
      const stuckRequestsQuery = `
        SELECT id, status
        FROM scan_requests
        WHERE 
          status NOT IN ($1, $2) AND
          created_at < NOW() - INTERVAL '15 minutes'
      `;
      
      const result = await query(stuckRequestsQuery, [STATES.COMPLETED, STATES.FAILED]);
      
      // Process each stuck request
      const processedIds = [];
      for (const row of result.rows) {
        // Mark as failed for now, could implement retry logic here
        await this.changeState(row.id, STATES.FAILED);
        processedIds.push(row.id);
      }
      
      return processedIds;
    } catch (error) {
      console.error('Error processing stuck requests:', error);
      throw error;
    }
  }
}

module.exports = new StateMachine();
