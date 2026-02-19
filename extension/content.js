chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "show_warning") {
        // Create the Banner
        const banner = document.createElement("div");
        banner.id = "siteshield-warning-banner";
        banner.style.cssText = `
            background-color: #d9534f !important;
            color: white !important;
            text-align: center !important;
            padding: 15px !important;
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            width: 100% !important;
            z-index: 2147483647 !important;
            font-family: Arial, sans-serif !important;
            font-weight: bold !important;
            font-size: 16px !important;
            box-shadow: 0 2px 10px rgba(0,0,0,0.5) !important;
        `;
        banner.innerHTML = `⚠️ SITESHIELD AI WARNING: This website is classified as ${request.status}. Use extreme caution! [ <a href="#" style="color:white;text-decoration:underline;" onclick="this.parentElement.remove();">Dismiss</a> ]`;
        
        document.body.prepend(banner);
    }
});