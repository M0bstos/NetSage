// tunnel.js - Start backend server and expose it with localtunnel
require('dotenv').config();
const localtunnel = require('localtunnel');
const { spawn } = require('child_process');
const port = process.env.PORT || 4000;

async function main() {
  try {
    // Start the server first
    console.log('Starting backend server...');
    const serverProcess = spawn('node', ['index.js'], { stdio: 'inherit' });
    
    // Give the server a moment to start
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Then start the tunnel
    console.log(`Starting tunnel to localhost:${port}...`);
    const tunnel = await localtunnel({ port });
    
    console.log('\n-------------------------------------------------------');
    console.log(`🚀 Your backend is now exposed at: ${tunnel.url}`);
    console.log(`📝 Configure your n8n webhook to point to:`);
    console.log(`   ${tunnel.url}/webhooks/scan-result`);
    console.log('\n🌌 TUNNEL ESTABLISHED');
    console.log('-------------------------------------------------------\n');
    
    // Handle server process events
    serverProcess.on('error', (err) => {
      console.error('Failed to start backend server:', err);
      tunnel.close();
      process.exit(1);
    });
    
    // Handle tunnel events
    tunnel.on('close', () => {
      console.log('Tunnel closed');
      serverProcess.kill();
      process.exit(0);
    });
    
    // Handle process termination
    process.on('SIGINT', () => {
      console.log('Shutting down server and tunnel...');
      serverProcess.kill();
      tunnel.close();
      process.exit(0);
    });
    
  } catch (err) {
    console.error('Error:', err);
    process.exit(1);
  }
}

main();
