require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const { pool } = require('./db');
const apiRoutes = require('./routes/api');
const webhookRoutes = require('./routes/webhooks');
const webSocketService = require('./services/webSocketService');
const schedulerService = require('./services/schedulerService');

// Create Express app
const app = express();
const PORT = process.env.PORT || 4000; // Changed to 4000 to avoid conflicts

// Create HTTP server
const server = http.createServer(app);

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' })); // Increased limit for potential large scan data

// Test database connection
pool.connect((err, client, done) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    console.log('Make sure your .env file has a valid DATABASE_URL setting.');
    console.log('For local development, you can use a PostgreSQL database or set up NeonDB.');
  } else {
    console.log('Successfully connected to the database');
    done();
  }
});

// API Routes
app.use('/api', apiRoutes);
app.use('/webhooks', webhookRoutes);

// Root route for API health check
app.get('/', (req, res) => {
  res.json({ 
    status: 'API is running',
    features: [
      'Real-time status updates via WebSockets',
      'Automated workflow with proper state management',
      'Scheduled tasks for data processing and report generation'
    ]
  });
});

// Initialize WebSocket service
webSocketService.initialize(server);

// Initialize scheduler service
schedulerService.initialize();

// Start the HTTP server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`WebSocket server available on ws://localhost:${PORT}`);
});
