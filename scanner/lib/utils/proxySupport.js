/**
 * Proxy Support Module
 * 
 * This module provides proxy functionality to enhance scanning capabilities
 * by routing traffic through proxies to avoid blocks and implement connection pooling.
 * 
 * Phase 4, Step 3 Implementation:
 * - Scanning through proxies to avoid blocks
 * - User-agent rotation
 * - Connection pooling for more efficient scanning
 * - Support for scanning through TOR (optional)
 */

const axios = require('axios');
const { URL } = require('url');

class ProxySupport {
  /**
   * Create a new ProxySupport instance
   * @param {Object} options - Options for proxy support
   * @param {Array} options.proxyList - List of proxy configurations
   * @param {boolean} options.enableTor - Enable TOR proxy support
   * @param {boolean} options.rotateUserAgents - Enable user agent rotation
   * @param {boolean} options.enableConnectionPooling - Enable connection pooling
   * @param {number} options.maxPoolSize - Maximum connection pool size
   * @param {number} options.poolTimeout - Connection pool timeout in ms
   * @param {string} options.torProxy - TOR proxy configuration
   */
  constructor(options = {}) {
    this.proxyList = options.proxyList || [];
    this.enableTor = options.enableTor !== false;
    this.rotateUserAgents = options.rotateUserAgents !== false;
    this.enableConnectionPooling = options.enableConnectionPooling !== false;
    this.maxPoolSize = options.maxPoolSize || 10;
    this.poolTimeout = options.poolTimeout || 30000;
    
    // TOR proxy configuration (SOCKS proxy on default TOR port)
    this.torProxy = options.torProxy || {
      protocol: 'socks5',
      host: '127.0.0.1',
      port: 9050
    };
    
    // Connection pools for different proxy configurations
    this.connectionPools = new Map();
    
    // User agent rotation list
    this.userAgents = [
      // Chrome browsers
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      
      // Firefox browsers
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
      'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
      
      // Safari browsers
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
      
      // Edge browsers
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
    ];
    
    this.currentUserAgentIndex = 0;
    this.currentProxyIndex = 0;
    
    console.log(`ProxySupport initialized - Proxies: ${this.proxyList.length}, TOR: ${this.enableTor}, User-Agent Rotation: ${this.rotateUserAgents}, Connection Pooling: ${this.enableConnectionPooling}`);
  }

  /**
   * Get the next proxy configuration in round-robin fashion
   * @param {boolean} includeTor - Whether to include TOR proxy in rotation
   * @returns {Object|null} - Proxy configuration or null if no proxies available
   */
  getNextProxy(includeTor = true) {
    const availableProxies = [...this.proxyList];
    
    // Add TOR proxy to the list if enabled and requested
    if (this.enableTor && includeTor) {
      availableProxies.push(this.torProxy);
    }
    
    if (availableProxies.length === 0) {
      return null;
    }
    
    const proxy = availableProxies[this.currentProxyIndex % availableProxies.length];
    this.currentProxyIndex++;
    
    return proxy;
  }

  /**
   * Get the next user agent in rotation
   * @returns {string} - User agent string
   */
  getNextUserAgent() {
    if (!this.rotateUserAgents) {
      return this.userAgents[0]; // Return the first one if rotation is disabled
    }
    
    const userAgent = this.userAgents[this.currentUserAgentIndex % this.userAgents.length];
    this.currentUserAgentIndex++;
    
    return userAgent;
  }

  /**
   * Create a configured axios instance with proxy and user agent rotation
   * @param {Object} options - Configuration options
   * @param {Object} options.proxy - Specific proxy to use (optional)
   * @param {string} options.userAgent - Specific user agent to use (optional)
   * @param {number} options.timeout - Request timeout in ms
   * @returns {Object} - Configured axios instance
   */
  createProxiedRequest(options = {}) {
    const proxy = options.proxy || this.getNextProxy();
    const userAgent = options.userAgent || this.getNextUserAgent();
    const timeout = options.timeout || 30000;
    
    const axiosConfig = {
      timeout: timeout,
      headers: {
        'User-Agent': userAgent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
      },
      // Disable SSL verification for scanning purposes (can be risky in production)
      httpsAgent: new (require('https').Agent)({
        rejectUnauthorized: false
      }),
      // Add some randomness to appear more human-like
      maxRedirects: 5,
      validateStatus: function (status) {
        return status < 500; // Accept any status code less than 500
      }
    };
    
    // Configure proxy if available
    if (proxy) {
      axiosConfig.proxy = {
        protocol: proxy.protocol || 'http',
        host: proxy.host,
        port: proxy.port,
        auth: proxy.auth ? {
          username: proxy.auth.username,
          password: proxy.auth.password
        } : undefined
      };
      
      console.log(`Using proxy: ${proxy.protocol || 'http'}://${proxy.host}:${proxy.port}`);
    }
    
    return axios.create(axiosConfig);
  }

  /**
   * Get a connection from the pool or create a new one
   * @param {string} proxyKey - Unique key for the proxy configuration
   * @param {Object} proxyConfig - Proxy configuration
   * @returns {Object} - Axios instance from pool
   */
  getPooledConnection(proxyKey, proxyConfig) {
    if (!this.enableConnectionPooling) {
      return this.createProxiedRequest({ proxy: proxyConfig });
    }
    
    if (!this.connectionPools.has(proxyKey)) {
      this.connectionPools.set(proxyKey, []);
    }
    
    const pool = this.connectionPools.get(proxyKey);
    
    // Return existing connection if available
    if (pool.length > 0) {
      return pool.pop();
    }
    
    // Create new connection if pool is empty but under max size
    if (pool.length < this.maxPoolSize) {
      return this.createProxiedRequest({ proxy: proxyConfig });
    }
    
    // Pool is at max capacity, create a new instance anyway
    return this.createProxiedRequest({ proxy: proxyConfig });
  }

  /**
   * Return a connection to the pool
   * @param {string} proxyKey - Unique key for the proxy configuration
   * @param {Object} connection - Axios instance to return to pool
   */
  returnConnectionToPool(proxyKey, connection) {
    if (!this.enableConnectionPooling) {
      return; // No pooling, just let it be garbage collected
    }
    
    if (this.connectionPools.has(proxyKey)) {
      const pool = this.connectionPools.get(proxyKey);
      if (pool.length < this.maxPoolSize) {
        pool.push(connection);
      }
    }
  }

  /**
   * Perform HTTP request through proxy with retries and fallbacks
   * @param {string} url - URL to request
   * @param {Object} options - Request options
   * @param {number} options.maxRetries - Maximum number of retries
   * @param {number} options.retryDelay - Delay between retries in ms
   * @param {boolean} options.fallbackToNoProxy - Whether to fallback to direct connection
   * @returns {Promise<Object>} - Response object
   */
  async makeProxiedRequest(url, options = {}) {
    const maxRetries = options.maxRetries || 3;
    const retryDelay = options.retryDelay || 1000;
    const fallbackToNoProxy = options.fallbackToNoProxy !== false;
    
    let lastError = null;
    const triedProxies = [];
    
    // Try with different proxies
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const proxy = this.getNextProxy();
        
        // Skip already tried proxies
        if (proxy && triedProxies.some(p => p.host === proxy.host && p.port === proxy.port)) {
          continue;
        }
        
        if (proxy) {
          triedProxies.push(proxy);
        }
        
        const proxyKey = proxy ? `${proxy.host}:${proxy.port}` : 'direct';
        const connection = this.getPooledConnection(proxyKey, proxy);
        
        console.log(`Attempting request to ${url} via ${proxy ? `${proxy.host}:${proxy.port}` : 'direct connection'} (attempt ${attempt + 1})`);
        
        const response = await connection.get(url);
        
        // Return connection to pool
        this.returnConnectionToPool(proxyKey, connection);
        
        return response;
        
      } catch (error) {
        lastError = error;
        console.log(`Request failed (attempt ${attempt + 1}): ${error.message}`);
        
        // Wait before retrying
        if (attempt < maxRetries - 1) {
          await this.delay(retryDelay * (attempt + 1)); // Exponential backoff
        }
      }
    }
    
    // If all proxy attempts failed and fallback is enabled, try direct connection
    if (fallbackToNoProxy) {
      try {
        console.log(`All proxy attempts failed, trying direct connection to ${url}`);
        const directConnection = this.createProxiedRequest({ proxy: null });
        const response = await directConnection.get(url);
        return response;
      } catch (error) {
        console.log(`Direct connection also failed: ${error.message}`);
        lastError = error;
      }
    }
    
    throw lastError || new Error('All proxy requests failed');
  }

  /**
   * Apply proxy configuration to Nmap command arguments
   * @param {Array} nmapArgs - Current Nmap arguments array
   * @param {Object} options - Additional options
   * @param {string} options.proxyChain - Proxy chain configuration for Nmap
   * @returns {Array} - Enhanced Nmap arguments with proxy support
   */
  applyProxyToNmap(nmapArgs, options = {}) {
    // Note: Nmap doesn't natively support HTTP proxies for all scan types
    // This is mainly for HTTP-based scans and script scans
    
    const proxy = options.proxy || this.getNextProxy();
    
    if (proxy && (proxy.protocol === 'http' || proxy.protocol === 'https')) {
      // For HTTP-based Nmap scripts
      nmapArgs.push(`--script-args=http.useragent="${this.getNextUserAgent()}"`);
      
      // If using HTTP proxy for script scans
      if (proxy.auth) {
        nmapArgs.push(`--script-args=http.proxy=${proxy.host}:${proxy.port},http.proxy-auth=${proxy.auth.username}:${proxy.auth.password}`);
      } else {
        nmapArgs.push(`--script-args=http.proxy=${proxy.host}:${proxy.port}`);
      }
    }
    
    // For SOCKS proxies (like TOR), we'd need to use proxychains or similar
    if (proxy && proxy.protocol === 'socks5') {
      console.log('Note: SOCKS proxy detected. Consider using proxychains with Nmap for SOCKS proxy support.');
    }
    
    return nmapArgs;
  }

  /**
   * Test proxy connectivity
   * @param {Object} proxy - Proxy configuration to test
   * @param {string} testUrl - URL to test connectivity with
   * @returns {Promise<boolean>} - Whether the proxy is working
   */
  async testProxy(proxy, testUrl = 'http://httpbin.org/ip') {
    try {
      const connection = this.createProxiedRequest({ proxy, timeout: 10000 });
      const response = await connection.get(testUrl);
      return response.status === 200;
    } catch (error) {
      console.log(`Proxy test failed for ${proxy.host}:${proxy.port} - ${error.message}`);
      return false;
    }
  }

  /**
   * Test all configured proxies and remove non-working ones
   * @param {string} testUrl - URL to test connectivity with
   * @returns {Promise<Array>} - Array of working proxies
   */
  async validateProxies(testUrl = 'http://httpbin.org/ip') {
    console.log('Validating proxy configurations...');
    const workingProxies = [];
    
    for (const proxy of this.proxyList) {
      const isWorking = await this.testProxy(proxy, testUrl);
      if (isWorking) {
        workingProxies.push(proxy);
        console.log(`✓ Proxy ${proxy.host}:${proxy.port} is working`);
      } else {
        console.log(`✗ Proxy ${proxy.host}:${proxy.port} is not working`);
      }
    }
    
    // Test TOR proxy if enabled
    if (this.enableTor) {
      const isTorWorking = await this.testProxy(this.torProxy, testUrl);
      if (isTorWorking) {
        console.log(`✓ TOR proxy ${this.torProxy.host}:${this.torProxy.port} is working`);
      } else {
        console.log(`✗ TOR proxy ${this.torProxy.host}:${this.torProxy.port} is not working`);
      }
    }
    
    this.proxyList = workingProxies;
    console.log(`Proxy validation complete. ${workingProxies.length} working proxies available.`);
    
    return workingProxies;
  }

  /**
   * Clean up connection pools
   */
  cleanup() {
    this.connectionPools.clear();
    console.log('Proxy connection pools cleaned up');
  }

  /**
   * Utility method to delay execution
   * @param {number} ms - Milliseconds to delay
   * @returns {Promise} - Promise that resolves after delay
   */
  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get current proxy statistics
   * @returns {Object} - Statistics about proxy usage
   */
  getProxyStats() {
    return {
      totalProxies: this.proxyList.length,
      torEnabled: this.enableTor,
      userAgentRotation: this.rotateUserAgents,
      connectionPooling: this.enableConnectionPooling,
      totalUserAgents: this.userAgents.length,
      currentProxyIndex: this.currentProxyIndex,
      currentUserAgentIndex: this.currentUserAgentIndex,
      poolSizes: Object.fromEntries(
        Array.from(this.connectionPools.entries()).map(([key, pool]) => [key, pool.length])
      )
    };
  }
}

module.exports = ProxySupport;
