document.addEventListener('DOMContentLoaded', () => {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        const tab = tabs[0];
        let currentUrl = tab.url;

        // Display domain specifically
        try {
            document.getElementById('url-domain').innerText = new URL(currentUrl).hostname;
        } catch(e) {
            document.getElementById('url-domain').innerText = currentUrl;
        }
        
        // If it's not a standard webpage (e.g. chrome:// extensions page)
        if (!currentUrl.startsWith('http')) {
            updateUI({
                status: "Safe",
                ai_score: "100%",
                hunter_risk: 0,
                method: "Browser Default"
            });
            return;
        }

        // Try getting from cache first (background.js saves it to avoid double-scans)
        chrome.storage.session.get([currentUrl], function(result) {
            if (result[currentUrl]) {
                updateUI(result[currentUrl]);
            } else {
                fetchBackend(currentUrl);
            }
        });
    });
});

function fetchBackend(url) {
    fetch('http://127.0.0.1:5000/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
    })
    .then(r => r.json())
    .then(data => {
        // Cache it for this session immediately
        let cacheObj = {};
        cacheObj[url] = data;
        chrome.storage.session.set(cacheObj);
        
        updateUI(data);
    })
    .catch(e => {
        console.error(e);
        setUIError();
    });
}

function updateUI(data) {
    // Hide loader
    document.getElementById('scan-state').innerHTML = `<span style="color:var(--color-safe); font-size:16px;">✓</span> Done`;
    
    // Set Status text
    const title = document.getElementById('status-title');
    title.innerText = data.status;
    title.className = 'status-' + data.status;

    // Animate Card Glow
    const card = document.getElementById('verdict-card');
    card.className = 'verdict-card glow-' + data.status;

    // Animate AI Score Bar
    document.getElementById('ai-value').innerText = data.ai_score || "N/A";
    const aiFill = document.getElementById('ai-confidence-fill');
    if (data.ai_score) {
        // Small delay for smooth animation after opening popup
        setTimeout(() => { aiFill.style.width = data.ai_score; }, 100);
    }

    // Animate Hunter Risk Bar
    const hunterScore = data.hunter_risk || 0;
    document.getElementById('hunter-value').innerText = `${hunterScore}/100`;
    const riskFill = document.getElementById('hunter-risk-fill');
    
    // Color risk bar conditionally
    if(hunterScore > 50) {
        riskFill.style.backgroundColor = 'var(--color-phish)';
        document.getElementById('hunter-value').className = 'metric-value status-Phishing';
    } else if (hunterScore >= 20) {
        riskFill.style.backgroundColor = 'var(--color-scam)';
        document.getElementById('hunter-value').className = 'metric-value status-Scam';
    } else {
        riskFill.style.backgroundColor = 'var(--color-safe)';
        document.getElementById('hunter-value').className = 'metric-value status-Safe';
    }

    setTimeout(() => { riskFill.style.width = `${hunterScore}%`; }, 100);

    // Method footer
    document.getElementById('api-method').innerText = `Engine: ${data.method || 'Heuristics'}`;
}

function setUIError() {
    document.getElementById('scan-state').innerText = "Offline";
    const title = document.getElementById('status-title');
    title.innerText = "System Offline";
    title.style.color = "var(--text-muted)";
    document.getElementById('api-method').innerText = "Make sure backend server is running";
}