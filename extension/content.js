// content.js - The "Behavioral Hunter"
(function() {
    function performHunterScan() {
        const domain = window.location.hostname;
        const forms = document.forms;
        const links = document.getElementsByTagName('a');
        
        // 1. Shadow Form Hunting (Data Exfiltration)
        let shadowForms = 0;
        for (let f of forms) {
            let action = f.action;
            if (action && action.startsWith('http')) {
                try {
                    let actionDomain = new URL(action).hostname;
                    // If data is sent to a different domain than the current one
                    if (actionDomain !== domain && !actionDomain.includes('google-analytics')) {
                        shadowForms++;
                    }
                } catch(e) {}
            }
        }

        // 2. Cloaking & Obfuscation Detection
        const hiddenIframes = document.querySelectorAll('iframe[style*="display:none"], iframe[style*="visibility:hidden"], iframe[width="0"], iframe[height="0"]');
        const hasRightClickDisabled = document.oncontextmenu !== null;

        // 3. UI Redirection Patterns
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

    // Send the DNA to the backend
    const dna = performHunterScan();
    chrome.runtime.sendMessage({ action: "check_url", dna: dna });
})();