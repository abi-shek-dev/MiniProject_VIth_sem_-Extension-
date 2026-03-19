// content.js - Now extracts Behavioral Features
function extractBehavioralFeatures() {
    const forms = document.getElementsByTagName('form');
    const scripts = document.getElementsByTagName('script');
    const iframes = document.getElementsByTagName('iframe');
    const links = document.getElementsByTagName('a');
    
    let suspiciousForms = 0;
    const currentDomain = window.location.hostname;

    // 1. Detect Form Hijacking (Data sent to a different domain)
    for (let f of forms) {
        let action = f.getAttribute('action');
        if (action && action.startsWith('http') && !action.includes(currentDomain)) {
            suspiciousForms++;
        }
    }

    return {
        url: window.location.href,
        form_count: forms.length,
        suspicious_forms: suspiciousForms,
        script_count: scripts.length,
        iframe_count: iframes.length,
        has_password_field: !!document.querySelector('input[type="password"]'),
        has_hidden_elements: !!document.querySelector('[style*="display:none"], [style*="visibility:hidden"]')
    };
}

// Send this "DNA" to the backend
chrome.runtime.sendMessage({ 
    action: "check_url", 
    dna: extractBehavioralFeatures() 
});