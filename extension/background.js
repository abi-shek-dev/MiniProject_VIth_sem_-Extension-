chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Listen for DNA scans from the content script
    if (request.action === "check_url" && request.dna && sender.tab) {
        let currentUrl = request.dna.url;
        let tabId = sender.tab.id;

        fetch('http://127.0.0.1:5000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dna: request.dna })  // DNA contains full behavioral scan
        })
        .then(response => response.json())
        .then(data => {
            console.log(`[SiteShield] Verdict for ${data.url}: ${data.status}`);

            // 1. Cache the result for the popup UI (instant load when clicked)
            let cacheObj = {};
            cacheObj[currentUrl] = data;
            chrome.storage.session.set(cacheObj);
            
            // 2. Set Browser Badge Action
            if (data.status !== "Safe") {
                chrome.action.setBadgeText({ text: "!", tabId: tabId });
                // Yellow for Scam/Defacement, Red for Phishing/Malicious
                if (data.status === "Scam" || data.status === "Defacement") {
                    chrome.action.setBadgeBackgroundColor({ color: "#FF9100" }); 
                } else {
                    chrome.action.setBadgeBackgroundColor({ color: "#FF1744" });
                }

                // 3. Show System Notification
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icons/icon128.png", 
                    title: "SiteShield AI Warning",
                    message: `This website has been classified as ${data.status}. Proceed with caution.`
                });

                // 4. Inject Banner into Page via Content Script
                chrome.tabs.sendMessage(tabId, {
                    action: "show_warning",
                    status: data.status,
                    risk: data.hunter_risk
                }).catch(() => console.log("Content script not ready for message."));

            } else {
                chrome.action.setBadgeText({ text: "OK", tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#00E676" });
            }
        })
        .catch(error => {
            console.error('[SiteShield] Backend Error:', error);
            chrome.action.setBadgeText({ text: "?", tabId: tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#888888" });
        });
    }
});