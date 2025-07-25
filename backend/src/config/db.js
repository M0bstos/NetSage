const { Pool } = require('pg');
require('dotenv').config();

// Create a singleton pool instance
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

/**
 * Execute a database query
 * @param {string} text - SQL query text
 * @param {Array} params - Query parameters
 * @returns {Promise} - Query result
 */
const query = (text, params) => pool.query(text, params);

module.exports = {
  query,
  pool
};
