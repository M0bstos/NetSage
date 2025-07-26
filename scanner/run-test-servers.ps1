# Run Test Servers for NetSage Scanner
# This script starts both the scanner server and the direct test server in separate terminal windows

# Start the scanner server in one terminal
Start-Process powershell -ArgumentList "-NoExit -Command `"cd 'C:\Users\ASUS\Desktop\Stuff\NetSage\scanner\' ; npm start`""

# Start the direct test server in another terminal
Start-Process powershell -ArgumentList "-NoExit -Command `"cd 'C:\Users\ASUS\Desktop\Stuff\NetSage\scanner\' ; node direct-server.js`""

Write-Host "Both servers started!"
Write-Host "Scanner server running at: http://localhost:3001"
Write-Host "Direct test interface available at: http://localhost:8090"
Write-Host ""
Write-Host "Press any key to exit (servers will continue running in their own windows)"
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
