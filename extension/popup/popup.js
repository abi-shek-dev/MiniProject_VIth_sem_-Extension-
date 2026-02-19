chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    let currentUrl = tabs[0].url;
    fetch('http://127.0.0.1:5000/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: currentUrl })
    })
    .then(r => r.json())
    .then(data => {
        const statusDiv = document.getElementById('status-text');
        statusDiv.innerText = data.status;
        statusDiv.className = 'status ' + data.status;
        document.getElementById('details').innerText = `Confidence: ${(data.confidence * 100).toFixed(1)}%`;
    });
});