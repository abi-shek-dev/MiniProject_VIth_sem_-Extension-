// content.js - Behavioral Hunter + Banner Injector
(function() {
    function performHunterScan() {
        const domain = window.location.hostname;
        const forms = document.forms;
        const links = document.getElementsByTagName('a');
        
        let shadowForms = 0;
        for (let f of forms) {
            let action = f.action;
            if (action && action.startsWith('http')) {
                try {
                    let actionDomain = new URL(action).hostname;
                    if (actionDomain !== domain && !actionDomain.includes('google')) {
                        shadowForms++;
                    }
                } catch(e) {}
            }
        }

        const hiddenIframes = document.querySelectorAll('iframe[style*="display:none"], iframe[style*="visibility:hidden"], iframe[width="0"], iframe[height="0"]');
        const hasRightClickDisabled = document.oncontextmenu !== null;

        let externalLinks = 0;
        for (let link of links) {
            if (link.href && !link.href.includes(domain) && link.href.startsWith('http')) {
                externalLinks++;
            }
        }

        return {
            url: window.location.href,
            has_password: !!document.querySelector('input[type="password"]'),
            shadow_forms: shadowForms,
            hidden_iframes: hiddenIframes.length,
            is_obfuscated: hasRightClickDisabled,
            ext_link_ratio: links.length > 0 ? (externalLinks / links.length) : 0,
            script_count: document.getElementsByTagName('script').length
        };
    }

    // 1. Instantly scan DNA and send to background script for analysis
    const dna = performHunterScan();
    chrome.runtime.sendMessage({ action: "check_url", dna: dna });

    // 2. Listen for Danger Verict from background script
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === "show_warning") {
            injectWarningBanner(request.status, request.risk);
        }
    });

    function injectWarningBanner(status, risk) {
        // Prevent multiple banners
        if(document.getElementById('siteshield-ai-banner')) return;

        const banner = document.createElement('div');
        banner.id = 'siteshield-ai-banner';
        
        // Match color to status
        let bgColor = status === "Scam" || status === "Defacement" ? "#ff9100" : "#d50000";

        // Inject modern premium CSS directly
        banner.style.cssText = `
            position: fixed;
            top: 0; left: 0; right: 0;
            background: linear-gradient(135deg, ${bgColor} 0%, #1a1a2e 100%);
            color: white;
            z-index: 2147483647; /* absolute max z-index */
            padding: 16px 24px;
            font-family: system-ui, -apple-system, sans-serif;
            font-size: 14px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            display: flex;
            align-items: center;
            justify-content: space-between;
            animation: slideDown 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
            border-bottom: 2px solid rgba(255,255,255,0.2);
        `;

        // Create animation dynamically
        const style = document.createElement('style');
        style.innerText = `
            @keyframes slideDown {
                from { transform: translateY(-100%); }
                to { transform: translateY(0); }
            }
            .siteshield-btn {
                background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.4);
                color: white; padding: 6px 16px; border-radius: 6px; cursor: pointer;
                font-weight: bold; transition: all 0.2s;
            }
            .siteshield-btn:hover { background: rgba(255,255,255,0.3); }
        `;
        document.head.appendChild(style);

        banner.innerHTML = `
            <div style="display:flex; align-items:center; gap: 12px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                    <line x1="12" y1="9" x2="12" y2="13"></line>
                    <line x1="12" y1="17" x2="12.01" y2="17"></line>
                </svg>
                <div>
                    <strong style="font-size: 16px; display:block;">SiteShield AI Warning</strong>
                    <span style="opacity:0.9;">This site is classified as <b>${status}</b>. It is highly recommended you leave immediately.</span>
                </div>
            </div>
            <div style="display:flex; gap: 10px;">
                <button class="siteshield-btn" onclick="window.history.back()">Go Back</button>
                <button class="siteshield-btn" id="siteshield-dismiss-btn" style="background:transparent; border-color:transparent;">Dismiss</button>
            </div>
        `;

        document.body.appendChild(banner);

        document.getElementById('siteshield-dismiss-btn').onclick = function() {
            banner.style.display = 'none';
        };
    }
})();