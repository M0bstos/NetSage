/**
 * WebSocket Service for real-time status updates
 * Provides a central hub for sending status updates to connected clients
 */
const socketIo = require('socket.io');
const stateMachine = require('./stateMachine');

class WebSocketService {
  /**
   * Initialize the WebSocket service with an HTTP server
   * @param {Object} server - HTTP server instance
   */
  initialize(server) {
    this.io = socketIo(server, {
      cors: {
        origin: '*', // For development, in production set to specific origins
        methods: ['GET', 'POST']
      }
    });

    // Set up connection event
    this.io.on('connection', (socket) => {
      console.log(`New client connected: ${socket.id}`);
      
      // Listen for scan subscriptions
      socket.on('subscribe', (requestId) => {
        console.log(`Client ${socket.id} subscribed to updates for scan ${requestId}`);
        socket.join(`scan:${requestId}`);
      });
      
      // Listen for unsubscribe events
      socket.on('unsubscribe', (requestId) => {
        console.log(`Client ${socket.id} unsubscribed from updates for scan ${requestId}`);
        socket.leave(`scan:${requestId}`);
      });
      
      // Handle disconnections
      socket.on('disconnect', () => {
        console.log(`Client disconnected: ${socket.id}`);
      });
    });

    // Listen to state machine events
    stateMachine.on('stateChanged', (data) => {
      this.sendScanUpdate(data);
    });

    console.log('WebSocket service initialized');
  }

  /**
   * Send a scan update to all clients subscribed to a specific scan
   * @param {Object} data - Update data including requestId and state
   */
  sendScanUpdate(data) {
    if (!this.io) {
      console.error('WebSocket service not initialized');
      return;
    }
    
    const { requestId, newState, prevState, timestamp } = data;
    
    this.io.to(`scan:${requestId}`).emit('scanUpdate', {
      requestId,
      status: newState,
      previousStatus: prevState,
      timestamp
    });
    
    console.log(`Sent update for scan ${requestId} to subscribed clients`);
  }

  /**
   * Send a general system notification to all connected clients
   * @param {string} message - Notification message
   * @param {string} type - Notification type (info, warning, error)
   */
  sendNotification(message, type = 'info') {
    if (!this.io) {
      console.error('WebSocket service not initialized');
      return;
    }
    
    this.io.emit('notification', { message, type, timestamp: new Date() });
  }
}

module.exports = new WebSocketService();
