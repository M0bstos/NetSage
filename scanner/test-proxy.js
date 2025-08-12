/**
 * Proxy Test Utility for NetSage Scanner
 * 
 * This script tests if your proxy configuration is working correctly.
 * It reads the proxy settings from your .env file and attempts to make
 * a request through the proxy to verify it's working.
 */

require('dotenv').config();
const axios = require('axios');

async function testProxy() {
  console.log('NetSage Scanner - Proxy Test Utility');
  console.log('====================================\n');
  
  // Check if proxy support is enabled
  const enableProxySupport = process.env.ENABLE_PROXY_SUPPORT === 'true';
  if (!enableProxySupport) {
    console.error('Error: Proxy support is not enabled in your .env file.');
    console.log('Please set ENABLE_PROXY_SUPPORT=true in your .env file.');
    return;
  }
  
  // Parse proxy list from environment variable
  let proxyList;
  try {
    proxyList = JSON.parse(process.env.PROXY_LIST || '[]');
  } catch (error) {
    console.error('Error: Failed to parse PROXY_LIST environment variable.');
    console.log('Please check the JSON format in your .env file.');
    return;
  }
  
  if (!proxyList.length) {
    console.error('Error: No proxies configured in PROXY_LIST environment variable.');
    console.log('Please add at least one proxy to your .env file.');
    return;
  }
  
  // Test each configured proxy
  console.log(`Testing ${proxyList.length} configured ${proxyList.length === 1 ? 'proxy' : 'proxies'}...\n`);
  
  for (const [index, proxyConfig] of proxyList.entries()) {
    console.log(`Testing proxy #${index + 1}: ${proxyConfig.protocol}://${proxyConfig.host}:${proxyConfig.port}`);
    
    if (proxyConfig.auth) {
      console.log(`Authentication: Username: ${proxyConfig.auth.username}, Password: ${'*'.repeat(proxyConfig.auth.password.length)}`);
    }
    
    try {
      const startTime = Date.now();
      const response = await axios({
        method: 'get',
        url: 'http://httpbin.org/ip',
        proxy: {
          host: proxyConfig.host,
          port: proxyConfig.port,
          protocol: proxyConfig.protocol,
          ...(proxyConfig.auth && { auth: proxyConfig.auth })
        },
        timeout: 10000
      });
      
      const responseTime = Date.now() - startTime;
      
      console.log('✅ Proxy test successful!');
      console.log(`Response time: ${responseTime}ms`);
      console.log(`Your IP appears as: ${response.data.origin}`);
    } catch (error) {
      console.error('❌ Proxy test failed:', error.message);
      console.log('\nTroubleshooting tips:');
      console.log('1. Check if the proxy server is online and accessible');
      console.log('2. Verify your proxy address and port are correct');
      console.log('3. If using authentication, check your username and password');
      console.log('4. Ensure your network allows connections to the proxy server');
    }
    
    console.log('\n-------------------------------------------\n');
  }
}

testProxy();
