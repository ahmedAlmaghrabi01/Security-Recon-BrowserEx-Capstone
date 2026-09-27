document.addEventListener('DOMContentLoaded', function() {
    const API_BASE_URL = 'http://localhost:8000';

    // Initialize UI elements
    const elements = {
        domainInput: document.getElementById('domainInput'),
        getCurrentDomainBtn: document.getElementById('getCurrentDomainBtn'),
        modeSelect: document.getElementById('modeSelect'),
        processSelect: document.getElementById('processSelect'),
        formatSelect: document.getElementById('formatSelect'),
        analyzeBtn: document.getElementById('analyzeBtn'),
        loading: document.getElementById('loading'),
        progressBar: document.getElementById('progressBar'),
        progressText: document.getElementById('progressText'),
        resultsDiv: document.getElementById('resultsDiv'), // Added missing element
        themeToggle: document.getElementById('themeToggle'),
        themeIcons: document.querySelectorAll('#themeToggle i')
    };

    // Check if all elements exist to prevent null reference errors
    for (const [key, value] of Object.entries(elements)) {
        if (!value) {
            console.error(`Element not found: ${key}`);
            showError(`Initialization error: ${key} not found in the page`);
            return;
        }
    }

    const PROCESSES = {
        simple: [
            { id: 'full', name: 'Full Report', endpoint: '/api/full/combined', formats: ['pdf'] },
            { id: 'attack', name: 'AI Attack Report', endpoint: '/api/bounty/analyze', formats: ['pdf'] },
            { id: 'defense', name: 'AI Defense Report', endpoint: '/api/defense/roadmap', formats: ['pdf'] },
            { id: 'executive', name: 'AI Non-Technical Report', endpoint: '/api/excutives/report', formats: ['pdf'] }
        ],
        pro: [
            { id: 'full', name: 'Full Report', endpoint: '/api/full/combined', formats: ['pdf'] },
            { id: 'attack', name: 'AI Attack Report', endpoint: '/api/bounty/analyze', formats: ['pdf'] },
            { id: 'defense', name: 'AI Defense Report', endpoint: '/api/defense/roadmap', formats: ['pdf'] },
            { id: 'executive', name: 'AI Non-Technical Report', endpoint: '/api/excutives/report', formats: ['pdf'] },
            { id: 'dns', name: 'DNS Retrieval', endpoint: '/api/dns/dns', formats: ['json', 'pdf'] },
            { id: 'whois', name: 'WHOIS Retrieval', endpoint: '/api/whois/whois', formats: ['json', 'pdf'] },
            { id: 'subdomains', name: 'Subdomain Enumeration', endpoint: '/api/subdomains/subdomains', formats: ['json', 'pdf'] },
            { id: 'tech', name: 'Tech Stack', endpoint: '/api/tech/tech', formats: ['json', 'pdf'] },
            { id: 'cve', name: 'CVE Analysis', endpoint: '/api/cve/cve', formats: ['json', 'pdf'] },
            { id: 'ssl', name: 'SSL/TLS Analysis', endpoint: '/api/ssl_tls/ssl_tls', formats: ['json', 'pdf'] }
        ]
    };

    // Update process options when mode changes
    elements.modeSelect.addEventListener('change', function() {
        const mode = this.value;
        updateProcessOptions(mode);
        elements.formatSelect.innerHTML = '<option value="">Select format</option>';
        elements.formatSelect.disabled = true; // Disable format until process is selected
    });

    function initTheme() {
        const savedTheme = localStorage.getItem('theme') || 'dark';
        document.body.className = savedTheme + '-mode'; // Clear previous classes
        updateThemeIcons(savedTheme);
    }
    
    function toggleTheme() {
        const newTheme = document.body.classList.contains('dark-mode') ? 'light' : 'dark';
        document.body.className = newTheme + '-mode'; // Atomic class update
        localStorage.setItem('theme', newTheme);
        updateThemeIcons(newTheme);
    }

    function updateThemeIcons(theme) {
        elements.themeIcons.forEach(icon => {
            icon.classList.toggle('hidden', 
                (icon.classList.contains('fa-moon') && theme === 'light') ||
                (icon.classList.contains('fa-sun') && theme === 'dark')
            );
        });
    }

    elements.themeToggle.addEventListener('click', toggleTheme);
    initTheme();

    // Get current domain from active tab
    elements.getCurrentDomainBtn.addEventListener('click', async function() {
        try {
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tabs[0]?.url) {
                const url = new URL(tabs[0].url);
                let domain = url.hostname;
    
                // Remove 'www.' if it appears at the beginning of the domain
                if (domain.startsWith('www.')) {
                    domain = domain.substring(4); // Remove the 'www.' part
                }
    
                elements.domainInput.value = domain;
            } else {
                showError('No active tab found');
            }
        } catch (error) {
            console.error('Error getting current domain:', error);
            showError('Unable to access the current tab');
        }
    });
    

    // Update format options when process changes
    elements.processSelect.addEventListener('change', function() {
        const mode = elements.modeSelect.value;
        const processId = this.value;
        if (processId) {
            const process = PROCESSES[mode].find(p => p.id === processId);
            if (process) {
                updateFormatOptions(process.formats);
                elements.formatSelect.disabled = false; // Enable format selection
            }
        } else {
            elements.formatSelect.innerHTML = '<option value="">Select format</option>';
            elements.formatSelect.disabled = true;
        }
    });

    elements.analyzeBtn.addEventListener('click', async function() {
        const domain = elements.domainInput.value.trim();
        const mode = elements.modeSelect.value;
        const processId = elements.processSelect.value;
        const format = elements.formatSelect.value;

        // Validation
        if (!domain) {
            showError('Please enter a domain');
            return;
        }
        if (!processId) {
            showError('Please select a process');
            return;
        }
        if (!format) {
            showError('Please select a format');
            return;
        }

        try {
            showLoading();
            elements.resultsDiv.innerHTML = ''; // Clear previous results
            const process = PROCESSES[mode].find(p => p.id === processId);
            if (!process) {
                throw new Error('Invalid process selected');
            }

            const result = await executeProcess(process, domain, format);

            // Display JSON in terminal if selected
            if (format === 'json' && result.results) {
                displayJsonTerminal(result.results, process.name);
            }

            // Handle download links
            if (result.download_links) {
                const downloadSection = document.createElement('div');
                downloadSection.className = 'download-section';
                result.download_links.forEach(link => {
                    const a = document.createElement('a');
                    a.href = link.url;
                    a.download = link.filename;
                    a.textContent = `Download ${link.name}`;
                    a.className = 'download-link';
                    downloadSection.appendChild(a);
                });
                elements.resultsDiv.appendChild(downloadSection);
            }

            updateProgress('Analysis complete!');
            setTimeout(hideLoading, 1000); // Hide loading after 1 second
        } catch (error) {
            console.error('Error:', error);
            showError(error.message);
        }
    });

    // Helper functions
    function updateProcessOptions(mode) {
        const processes = PROCESSES[mode] || [];
        elements.processSelect.innerHTML = '<option value="">Select process</option>';
        processes.forEach(process => {
            const option = document.createElement('option');
            option.value = process.id;
            option.textContent = process.name;
            elements.processSelect.appendChild(option);
        });
    }

    function updateFormatOptions(formats) {
        elements.formatSelect.innerHTML = '';
        formats.forEach(format => {
            const option = document.createElement('option');
            option.value = format;
            option.textContent = format.toUpperCase();
            elements.formatSelect.appendChild(option);
        });
        if (formats.length === 1) {
            elements.formatSelect.value = formats[0]; // Auto-select if only one format
        }
    }


    function generateTimestamp() {
        return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    }

    
    async function executeProcess(process, domain, format) {
        try {
            updateProgress(`Fetching ${process.name} in ${format.toUpperCase()} format...`);
    
            // Construct the URL, and append ?format=pdf or ?format=json based on the format
            let url = `${API_BASE_URL}${process.endpoint}/${domain}`;
            if (format === 'pdf') {
                url += `?format=pdf`;
            } else if (format === 'json') {
                url += `?format=json`;
            }
    
            const acceptHeader = format === 'pdf' ? 'application/pdf' : 'application/json';
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Accept': acceptHeader
                }
            });
    
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`API returned ${response.status}: ${errorText}`);
            }

            const timestamp = generateTimestamp(); // Unified timestamp

            if (format === 'pdf') {
                const contentDisposition = response.headers.get('Content-Disposition');
                const filename = contentDisposition
                    ? contentDisposition.split('filename=')[1].replace(/"/g, '')
                    : `${domain}_${process.id}_${timestamp}.pdf`; // Unified format with timestamp
                const blob = await response.blob();
                const pdfUrl = URL.createObjectURL(blob);
                return {
                    download_links: [{
                        name: `${process.name} (PDF)`,
                        url: pdfUrl,
                        format: 'pdf',
                        filename: filename
                    }]
                };
            } else {
                const data = await response.json();
                const jsonBlob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const jsonUrl = URL.createObjectURL(jsonBlob);

                return {
                    results: { [process.id]: data },
                    download_links: [{
                        name: `${process.name} (JSON)`,
                        url: jsonUrl,
                        format: 'json',
                        filename: `${domain}_${process.id}_${timestamp}.json` // Unified format with timestamp
                    }]
                };
            }

    
        } catch (error) {
            console.error(`Error fetching ${process.name} in ${format.toUpperCase()} format:`, error);
            throw error;
        }
    }
    
    
    // Function to check domain reachability using a HEAD request
    async function checkDomainReachability(domain) {
        try {
            const response = await fetch(`https://${domain}`, { method: 'HEAD', mode: 'no-cors' });
            return response.ok;
        } catch (error) {
            console.error(`Error checking domain ${domain}:`, error);
            return false;
        }
    }
    


    function showLoading() {
        elements.loading.classList.remove('hidden');
        elements.analyzeBtn.disabled = true;
        updateProgress('Initializing...');
    }

    function hideLoading() {
        elements.loading.classList.add('hidden');
        elements.analyzeBtn.disabled = false;
    }

    function updateProgress(message) {
        elements.progressText.textContent = message;
    }

    function showError(message) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        errorDiv.innerHTML = `
            <i class="fas fa-exclamation-circle"></i>
            <p>${message}</p>
        `;
        const container = document.querySelector('.container');
        container.insertBefore(errorDiv, container.firstChild);
        hideLoading();
        setTimeout(() => errorDiv.remove(), 7000);
    }

    function displayJsonTerminal(data, title) {
        const existingTerminal = document.querySelector('.json-terminal-container');
        if (existingTerminal) existingTerminal.remove();

        const terminalContainer = document.createElement('div');
        terminalContainer.className = 'json-terminal-container';

        const terminalHeader = document.createElement('div');
        terminalHeader.className = 'json-terminal-header';
        const terminalTitle = document.createElement('div');
        terminalTitle.className = 'json-terminal-title';
        terminalTitle.textContent = `${title} Data`;
        terminalHeader.appendChild(terminalTitle);

        const copyButton = document.createElement('button');
        copyButton.className = 'json-terminal-copy-btn';
        copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
        copyButton.addEventListener('click', () => {
            const jsonText = JSON.stringify(data, null, 2);
            navigator.clipboard.writeText(jsonText)
                .then(() => {
                    copyButton.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    setTimeout(() => {
                        copyButton.innerHTML = '<i class="fas fa-copy"></i> Copy';
                    }, 2000);
                })
                .catch(err => console.error('Failed to copy JSON:', err));
        });
        terminalHeader.appendChild(copyButton);
        terminalContainer.appendChild(terminalHeader);

        const terminalContent = document.createElement('pre');
        terminalContent.className = 'json-terminal-content';
        terminalContent.textContent = JSON.stringify(data, null, 2);
        terminalContainer.appendChild(terminalContent);

        elements.resultsDiv.appendChild(terminalContainer);
        terminalContainer.classList.add('responsive-terminal');
        
        if(window.innerWidth < 420) {
            terminalContainer.classList.add('responsive-terminal');
        }
    
        // Add resize handler for dynamic adjustments
        window.addEventListener('resize', () => {
            if(window.innerWidth < 420) {
                terminalContainer.classList.add('responsive-terminal');
            } else {
                terminalContainer.classList.remove('responsive-terminal');
            }
        });
    }

    function addStyles() {
        const style = document.createElement('style');
        style.textContent = `
            .json-terminal-container { margin: 20px 0; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); }
            .json-terminal-header { background-color: #343a40; color: white; padding: 10px 15px; display: flex; justify-content: space-between; align-items: center; }
            .json-terminal-title { font-weight: 600; }
            .json-terminal-copy-btn { background-color: transparent; border: 1px solid rgba(255, 255, 255, 0.4); color: white; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; transition: all 0.2s; }
            .json-terminal-copy-btn:hover { background-color: rgba(255, 255, 255, 0.1); }
            .json-terminal-content { background-color: #2a2a2a; color: #f8f8f8; padding: 15px; margin: 0; max-height: 300px; overflow-y: auto; font-family: 'Consolas', 'Monaco', monospace; font-size: 13px; white-space: pre-wrap; line-height: 1.5; }
            .json-terminal-content::-webkit-scrollbar { width: 8px; }
            .json-terminal-content::-webkit-scrollbar-track { background: #1e1e1e; }
            .json-terminal-content::-webkit-scrollbar-thumb { background: #555; border-radius: 4px; }
            .json-terminal-content::-webkit-scrollbar-thumb:hover { background: #777; }
            .download-section { margin-top: 10px; }
            .download-link { display: block; margin: 5px 0; color: #007bff; text-decoration: none; }
            .download-link:hover { text-decoration: underline; }
            .error-message { background-color: #f8d7da; color: #721c24; padding: 10px; border-radius: 5px; margin-bottom: 10px; display: flex; align-items: center; }
            .error-message i { margin-right: 10px; }
        `;
        document.head.appendChild(style);
    }

    updateProcessOptions(elements.modeSelect.value);
    elements.formatSelect.disabled = true; 
    addStyles();
});
