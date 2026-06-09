document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('fileInput');
    const dropzoneText = document.getElementById('dropzoneText');
    const uploadForm = document.getElementById('uploadForm');
    const fileDetails = document.getElementById('fileDetails');
    const fileNameEl = document.getElementById('fileName');
    const fileSizeEl = document.getElementById('fileSize');
    const terminalPanel = document.getElementById('uploadTerminal');
    const terminalLogs = document.getElementById('terminalLogs');
    const btnSubmit = document.getElementById('btnSubmit');

    if (!dropzone) return;

    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    // Highlight drop zone on drag over
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, unhighlight, false);
    });

    // Handle dropped files
    dropzone.addEventListener('drop', handleDrop, false);

    // Handle selected files
    fileInput.addEventListener('change', handleFileSelect, false);

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight() {
        dropzone.classList.add('highlight');
        dropzone.style.borderColor = 'var(--primary)';
        dropzone.style.background = 'rgba(0, 240, 255, 0.05)';
    }

    function unhighlight() {
        dropzone.classList.remove('highlight');
        dropzone.style.borderColor = 'var(--border-color)';
        dropzone.style.background = 'var(--bg-surface)';
    }

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length) {
            fileInput.files = files;
            processFile(files[0]);
        }
    }

    function handleFileSelect(e) {
        const files = e.target.files;
        if (files.length) {
            processFile(files[0]);
        }
    }

    function processFile(file) {
        const validExtensions = ['.csv', '.txt', '.log'];
        const fileExt = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
        
        if (!validExtensions.includes(fileExt)) {
            appendLog(`[ERROR] File format '${fileExt}' not supported. Please upload .csv, .txt, or log files.`, 'danger');
            fileInput.value = '';
            fileDetails.style.display = 'none';
            btnSubmit.disabled = true;
            return;
        }

        // Show details
        fileNameEl.textContent = file.name;
        fileSizeEl.textContent = formatBytes(file.size);
        fileDetails.style.display = 'block';
        btnSubmit.disabled = false;

        terminalLogs.innerHTML = '';
        terminalPanel.style.display = 'block';

        appendLog(`[INFO] Loaded file: ${file.name}`, 'info');
        appendLog(`[INFO] Size: ${formatBytes(file.size)}`, 'info');
        appendLog(`[INFO] Parsing structures...`, 'info');

        // Read a preview of the file client-side to simulate log parsing
        const reader = new FileReader();
        reader.onload = function(e) {
            const text = e.target.result;
            const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
            const ips = text.match(ipRegex) || [];
            const uniqueIps = [...new Set(ips)];
            
            appendLog(`[SUCCESS] Extracted ${ips.length} total IP addresses.`, 'success');
            appendLog(`[SUCCESS] Found ${uniqueIps.length} unique targets.`, 'success');
            appendLog(`[READY] Threat Intelligence pipeline ready for bulk ingestion. Click 'Run Analysis' below.`, 'warning');
        };
        reader.readAsText(file.slice(0, 1024 * 50)); // Read first 50KB for analysis preview
    }

    function appendLog(message, type = 'info') {
        const line = document.createElement('div');
        line.className = `console-line ${type}`;
        
        const ts = new Date().toLocaleTimeString();
        line.innerHTML = `<span class="console-timestamp">[${ts}]</span> <span>${message}</span>`;
        
        terminalLogs.appendChild(line);
        terminalPanel.scrollTop = terminalPanel.scrollHeight;
    }

    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
});
