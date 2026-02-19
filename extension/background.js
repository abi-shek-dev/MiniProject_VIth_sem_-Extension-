chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        
        fetch('http://127.0.0.1:5000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: tab.url })
        })
        .then(response => response.json())
        .then(data => {
            console.log("Verdict for " + data.url + ": " + data.status);
            
            if (data.status !== "Safe") {
                // 1. Update Badge
                chrome.action.setBadgeText({ text: "!", tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });

                // 2. Show Browser Notification
                chrome.notifications.create({
                    type: "basic",
                    iconUrl: "icons/icon128.png", 
                    title: "Security Alert!",
                    message: `Warning: This site is classified as ${data.status}!`
                });

                // 3. SEND MESSAGE TO CONTENT SCRIPT (This was misplaced)
                // This tells content.js to inject the red banner
                chrome.tabs.sendMessage(tabId, {
                    action: "show_warning",
                    status: data.status
                });

            } else {
                chrome.action.setBadgeText({ text: "OK", tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: "#00FF00" });
            }
        })
        .catch(error => console.error('Error connecting to backend:', error));
    }
});