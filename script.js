document.addEventListener('DOMContentLoaded', () => {
    const openScanModalBtn = document.getElementById('openScanModalBtn');
    const scanModal = document.getElementById('scanModal');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const scanWebsiteBtn = document.getElementById('scanWebsiteBtn');
    const websiteInput = document.getElementById('websiteInput');

   
    const N8N_WEBHOOK_URL = 'http://localhost:5678/webhook-test/scan-website'; 

    const showModal = () => {
        scanModal.classList.add('show-modal');
        websiteInput.focus(); 
    };

    const hideModal = () => {
        scanModal.classList.remove('show-modal');
        websiteInput.value = ''; 
    };

    if (openScanModalBtn) {
        openScanModalBtn.addEventListener('click', showModal);
    }

    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', hideModal);
    }

    if (scanModal) {
        scanModal.addEventListener('click', (e) => {
            if (e.target === scanModal) {
                hideModal();
            }
        });
    }

    if (scanWebsiteBtn) {
        scanWebsiteBtn.addEventListener('click', async () => {
            const websiteUrl = websiteInput.value.trim();
            if (websiteUrl) {
                showCustomMessageBox(`Initiating scan for: ${websiteUrl}... Please wait.`);
                hideModal(); 

                try {
                    const response = await fetch(N8N_WEBHOOK_URL, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ websiteUrl: websiteUrl }), 
                    });

                    if (response.ok) {
                        const result = await response.json();
                      
                        if (result && result.report) {
                            showCustomMessageBox(`Scan complete! Report:\n\n${result.report}`);
                            console.log('Scan Report:', result.report);
                            
                        } else {
                            showCustomMessageBox('Scan initiated successfully, but no report was returned by n8n.');
                            console.log('n8n response:', result);
                        }
                    } else {
                        const errorText = await response.text();
                        showCustomMessageBox(`Error initiating scan: ${response.status} - ${errorText}`);
                        console.error('Error response from n8n:', response.status, errorText);
                    }
                } catch (error) {
                    showCustomMessageBox(`Failed to connect to n8n: ${error.message}. Ensure n8n is running and the URL is correct.`);
                    console.error('Fetch error:', error);
                }
            } else {
                showCustomMessageBox('Please enter a website or domain name to scan.');
            }
        });
    }

   
    function showCustomMessageBox(message) {
        let messageBox = document.getElementById('customMessageBox');
        if (!messageBox) {
            messageBox = document.createElement('div');
            messageBox.id = 'customMessageBox';
            messageBox.className = 'fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-gray-900 text-white p-6 rounded-lg shadow-xl z-[1001] opacity-0 scale-90 transition-all duration-300 ease-in-out max-w-sm text-center';
            messageBox.innerHTML = `
                <p class="mb-4 whitespace-pre-wrap">${message}</p>
                <button class="bg-purple-600 hover:bg-purple-700 text-white py-2 px-4 rounded-lg text-sm font-medium" onclick="this.parentNode.classList.remove('opacity-100', 'scale-100'); setTimeout(() => this.parentNode.remove(), 300);">OK</button>
            `;
            document.body.appendChild(messageBox);
            
            setTimeout(() => {
                messageBox.classList.add('opacity-100', 'scale-100');
            }, 10);
        } else {
            messageBox.querySelector('p').innerText = message;
            messageBox.classList.add('opacity-100', 'scale-100');
        }
    }
});