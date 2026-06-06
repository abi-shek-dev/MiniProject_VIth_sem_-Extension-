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

    // 2. Listen for verdict from background script
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === "show_warning") {
            const isFullScreen = request.status === "Scam" || request.status === "Phishing" || request.status === "Malicious";
            if (isFullScreen) {
                injectFullScreenBlock(request.status, request.risk);
            } else {
                injectWarningBanner(request.status, request.risk);
            }
        }
    });

    // ── Full-screen blocking overlay for Scam / Phishing / Malicious ──────────
    function injectFullScreenBlock(status, risk) {
        if (document.getElementById('siteshield-fullscreen')) return;

        const style = document.createElement('style');
        style.innerText = `
            @keyframes ss-fadeIn {
                from { opacity: 0; transform: scale(0.97); }
                to   { opacity: 1; transform: scale(1); }
            }
            @keyframes ss-pulse {
                0%, 100% { box-shadow: 0 0 0 0 rgba(255,23,68,0.5); }
                50%       { box-shadow: 0 0 0 20px rgba(255,23,68,0); }
            }
            @keyframes ss-shake {
                0%,100% { transform: translateX(0); }
                20%     { transform: translateX(-8px); }
                40%     { transform: translateX(8px); }
                60%     { transform: translateX(-5px); }
                80%     { transform: translateX(5px); }
            }
            #siteshield-fullscreen {
                position: fixed; inset: 0; z-index: 2147483647;
                background: linear-gradient(135deg, #0d0d0d 0%, #1a0000 55%, #2d0a0a 100%);
                display: flex; align-items: center; justify-content: center;
                font-family: system-ui, -apple-system, sans-serif;
                animation: ss-fadeIn 0.4s cubic-bezier(0.23,1,0.32,1) forwards;
                overflow: hidden;
            }
            #siteshield-fullscreen .ss-glow {
                position: absolute; width: 700px; height: 700px; border-radius: 50%;
                background: radial-gradient(circle, rgba(255,23,68,0.14) 0%, transparent 70%);
                top: 50%; left: 50%; transform: translate(-50%, -50%);
                pointer-events: none;
            }
            #siteshield-fullscreen .ss-card {
                position: relative; z-index: 1;
                background: rgba(255,255,255,0.04);
                border: 1px solid rgba(255,23,68,0.3);
                border-radius: 24px; padding: 56px 64px;
                max-width: 560px; width: 90%; text-align: center;
                backdrop-filter: blur(24px);
                animation: ss-shake 0.5s ease 0.45s both;
            }
            #siteshield-fullscreen .ss-shield {
                width: 90px; height: 90px; border-radius: 50%;
                background: linear-gradient(135deg, #ff1744, #b71c1c);
                display: flex; align-items: center; justify-content: center;
                margin: 0 auto 28px;
                animation: ss-pulse 2s infinite;
            }
            #siteshield-fullscreen .ss-shield svg { width: 46px; height: 46px; }
            #siteshield-fullscreen .ss-badge {
                display: inline-block;
                background: rgba(255,23,68,0.12);
                border: 1px solid rgba(255,23,68,0.45);
                color: #ff5252; font-size: 11px; font-weight: 700;
                letter-spacing: 2px; text-transform: uppercase;
                padding: 4px 14px; border-radius: 20px; margin-bottom: 20px;
            }
            #siteshield-fullscreen h1 {
                color: #fff; font-size: 30px; font-weight: 800;
                margin: 0 0 12px; line-height: 1.25;
            }
            #siteshield-fullscreen .ss-sub {
                color: rgba(255,255,255,0.58); font-size: 15px; line-height: 1.65;
                margin: 0 0 24px;
            }
            #siteshield-fullscreen .ss-domain {
                background: rgba(255,23,68,0.08);
                border: 1px solid rgba(255,23,68,0.22);
                color: #ff5252; font-size: 13px; font-family: monospace;
                padding: 9px 18px; border-radius: 8px;
                margin-bottom: 28px; word-break: break-all;
            }
            #siteshield-fullscreen .ss-risk-label {
                color: rgba(255,255,255,0.4); font-size: 12px;
                margin-bottom: 7px; text-align: left;
            }
            #siteshield-fullscreen .ss-risk-track {
                background: rgba(255,255,255,0.07); border-radius: 8px;
                height: 8px; margin-bottom: 32px; overflow: hidden;
            }
            #siteshield-fullscreen .ss-risk-fill {
                height: 100%; border-radius: 8px;
                background: linear-gradient(90deg, #ff6d00, #ff1744);
                width: 0%; transition: width 1.1s cubic-bezier(0.23,1,0.32,1);
            }
            #siteshield-fullscreen .ss-btns {
                display: flex; gap: 12px; justify-content: center;
            }
            #siteshield-fullscreen .ss-btn-primary {
                flex: 1; padding: 14px; border-radius: 12px; border: none; cursor: pointer;
                background: linear-gradient(135deg, #ff1744, #b71c1c);
                color: #fff; font-size: 15px; font-weight: 700;
                transition: opacity 0.2s, transform 0.15s;
            }
            #siteshield-fullscreen .ss-btn-primary:hover { opacity: 0.85; transform: translateY(-1px); }
            #siteshield-fullscreen .ss-btn-secondary {
                padding: 14px 22px; border-radius: 12px; cursor: pointer;
                background: transparent; border: 1px solid rgba(255,255,255,0.15);
                color: rgba(255,255,255,0.38); font-size: 13px;
                transition: all 0.2s;
            }
            #siteshield-fullscreen .ss-btn-secondary:hover {
                border-color: rgba(255,255,255,0.3);
                color: rgba(255,255,255,0.6);
            }
        `;
        document.head.appendChild(style);

        const overlay = document.createElement('div');
        overlay.id = 'siteshield-fullscreen';
        const riskPct = Math.min(risk || 100, 100);
        const hostname = window.location.hostname;

        overlay.innerHTML = `
            <div class="ss-glow"></div>
            <div class="ss-card">
                <div class="ss-shield">
                    <svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <circle cx="12" cy="16" r="0.5" fill="white"/>
                    </svg>
                </div>
                <div class="ss-badge">⚠&nbsp; SiteShield AI &mdash; ${status} Detected</div>
                <h1>Dangerous Website Blocked</h1>
                <p class="ss-sub">Our AI engine has classified this page as <strong style="color:#ff5252">${status}</strong>. This site may attempt to steal your data, credentials, or install malware on your device.</p>
                <div class="ss-domain">${hostname}</div>
                <div class="ss-risk-label">Threat Risk Score &mdash; ${riskPct}%</div>
                <div class="ss-risk-track">
                    <div class="ss-risk-fill" id="ss-risk-fill"></div>
                </div>
                <div class="ss-btns">
                    <button class="ss-btn-primary" onclick="window.history.back()">&#8592; Go Back to Safety</button>
                    <button class="ss-btn-secondary" id="ss-dismiss">Proceed Anyway</button>
                </div>
            </div>
        `;

        // Block scroll behind overlay
        document.body.style.overflow = 'hidden';
        document.body.appendChild(overlay);

        // Animate risk bar after paint
        requestAnimationFrame(() => {
            setTimeout(() => {
                const fill = document.getElementById('ss-risk-fill');
                if (fill) fill.style.width = riskPct + '%';
            }, 80);
        });

        document.getElementById('ss-dismiss').onclick = () => {
            overlay.style.opacity = '0';
            overlay.style.transition = 'opacity 0.3s';
            document.body.style.overflow = '';
            setTimeout(() => overlay.remove(), 300);
        };
    }

    // ── Slim top banner for Suspicious ────────────────────────────────────────
    function injectWarningBanner(status, risk) {
        if (document.getElementById('siteshield-ai-banner')) return;

        const style = document.createElement('style');
        style.innerText = `
            @keyframes slideDown {
                from { transform: translateY(-100%); }
                to   { transform: translateY(0); }
            }
            .siteshield-btn {
                background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.4);
                color: white; padding: 6px 16px; border-radius: 6px; cursor: pointer;
                font-weight: bold; transition: all 0.2s;
            }
            .siteshield-btn:hover { background: rgba(255,255,255,0.3); }
        `;
        document.head.appendChild(style);

        const banner = document.createElement('div');
        banner.id = 'siteshield-ai-banner';
        banner.style.cssText = `
            position: fixed; top: 0; left: 0; right: 0;
            background: linear-gradient(135deg, #FF9100 0%, #1a1a2e 100%);
            color: white; z-index: 2147483647; padding: 16px 24px;
            font-family: system-ui, -apple-system, sans-serif; font-size: 14px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            display: flex; align-items: center; justify-content: space-between;
            animation: slideDown 0.5s cubic-bezier(0.175,0.885,0.32,1.275) forwards;
            border-bottom: 2px solid rgba(255,255,255,0.2);
        `;

        banner.innerHTML = `
            <div style="display:flex; align-items:center; gap:12px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                    <line x1="12" y1="9" x2="12" y2="13"></line>
                    <line x1="12" y1="17" x2="12.01" y2="17"></line>
                </svg>
                <div>
                    <strong style="font-size:16px; display:block;">SiteShield AI Warning</strong>
                    <span style="opacity:0.9;">This site is classified as <b>${status}</b>. Proceed with caution.</span>
                </div>
            </div>
            <div style="display:flex; gap:10px;">
                <button class="siteshield-btn" onclick="window.history.back()">Go Back</button>
                <button class="siteshield-btn" id="siteshield-dismiss-btn" style="background:transparent; border-color:transparent;">Dismiss</button>
            </div>
        `;

        document.body.appendChild(banner);
        document.getElementById('siteshield-dismiss-btn').onclick = () => banner.style.display = 'none';
    }
})();