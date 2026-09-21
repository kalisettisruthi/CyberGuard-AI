// static/js/script.js
// AI Cyber Threat Detection System — Frontend logic

document.addEventListener('DOMContentLoaded', () => {
    initNav();
    initScrollTop();
    initWebsite();
    initEXE();
});

// ---------------------------------------------------------------
// Navigation (mobile toggle)
// ---------------------------------------------------------------
function initNav() {
    const toggle = document.getElementById('navToggle');
    const links = document.getElementById('navLinks');
    if (!toggle || !links) return;
    toggle.addEventListener('click', () => {
        links.classList.toggle('active');
        const i = toggle.querySelector('i');
        if (i) { i.classList.toggle('fa-bars'); i.classList.toggle('fa-times'); }
    });
}

// ---------------------------------------------------------------
// Scroll-to-top button
// ---------------------------------------------------------------
function initScrollTop() {
    const btn = document.getElementById('scrollTopBtn');
    if (!btn) return;
    window.addEventListener('scroll', () => {
        btn.classList.toggle('visible', window.scrollY > 300);
    });
    btn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------
function show(id, yes) {
    const el = document.getElementById(id);
    if (el) el.style.display = yes ? 'block' : 'none';
}
function set(id, text, cls) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    if (cls) el.className = cls;
}
function applyRiskLevels(risk) {
    const map = { Low: 'risk-low', Medium: 'risk-medium', High: 'risk-high' };
    set('riskLevel', risk + ' Risk', 'result-value text-' + risk.toLowerCase());
    const badge = document.getElementById('riskBadge');
    if (badge) badge.className = 'result-badge ' + (map[risk] || '');
    if (badge) badge.textContent = risk + ' Risk';
}

// ---------------------------------------------------------------
// Website Threat Detection
// ---------------------------------------------------------------
function initWebsite() {
    const input = document.getElementById('websiteUrl');
    const btn   = document.getElementById('detectBtn');
    const again = document.getElementById('scanAgainBtn');
    if (!input || !btn) return;

    btn.addEventListener('click', () => {
        const url = input.value.trim();
        if (!url) return alert('Please enter a URL');

        show('loadingSection', true);
        show('resultsSection', false);
        btn.disabled = true;

        fetch('/predict-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        })
        .then(r => r.json().then(d => ({ ok: r.ok, d })))
        .then(({ ok, d }) => {
            show('loadingSection', false);
            btn.disabled = false;
            if (!ok) return alert('Error: ' + (d.error || 'Unknown'));

            set('scannedUrl', url);
            set('predictionValue', d.prediction,
                'result-value ' + (d.prediction === 'Safe' ? 'text-success' : 'text-danger'));
            set('confidenceValue', d.confidence);
            const bar = document.getElementById('confidenceBar');
            if (bar) bar.style.width = d.confidence + '%';
            applyRiskLevels(d.risk_level);
            set('recommendationText', d.recommendation);
            const list = document.getElementById('recommendationList');
            if (list) list.innerHTML = '';
            show('resultsSection', true);
        })
        .catch(e => {
            console.error(e);
            show('loadingSection', false);
            btn.disabled = false;
            alert('Server error');
        });
    });

    if (again) again.addEventListener('click', () => {
        input.value = '';
        show('resultsSection', false);
    });
}

// ---------------------------------------------------------------
// EXE Malware Detection
// ---------------------------------------------------------------
function initEXE() {
    const input  = document.getElementById('fileInput');
    const browse = document.getElementById('browseBtn');
    const area   = document.getElementById('uploadArea');
    const card   = document.getElementById('fileCard');
    const scan   = document.getElementById('scanBtn');
    let file = null;

    if (browse && input) browse.addEventListener('click', e => { e.stopPropagation(); input.click(); });
    if (area && input)   area.addEventListener('click', () => input.click());

    function setFile(f) {
        if (!f) return;
        if (!f.name.toLowerCase().endsWith('.exe')) return alert('Only .exe files allowed');
        file = f;
        set('fileName', f.name);
        set('fileSize', (f.size / (1024 * 1024)).toFixed(2) + ' MB');
        show('fileCard', true);
        if (scan) scan.disabled = false;
    }

    if (input) input.addEventListener('change', () => setFile(input.files[0]));

    if (area) {
        area.addEventListener('dragover', e => { e.preventDefault(); area.classList.add('drag-over'); });
        area.addEventListener('dragleave', () => area.classList.remove('drag-over'));
        area.addEventListener('drop', e => {
            e.preventDefault();
            area.classList.remove('drag-over');
            setFile(e.dataTransfer.files[0]);
        });
    }

    const remove = document.getElementById('removeFileBtn');
    if (remove) remove.addEventListener('click', () => {
        file = null;
        if (input) input.value = '';
        show('fileCard', false);
        if (scan) scan.disabled = true;
    });

    if (scan) scan.addEventListener('click', () => {
        if (!file) return alert('Please select a file first');

        show('loadingSection', true);
        show('resultsSection', false);
        scan.disabled = true;

        const fd = new FormData();
        fd.append('file', file);

        fetch('/predict-exe', { method: 'POST', body: fd })
        .then(r => r.json().then(d => ({ ok: r.ok, d })))
        .then(({ ok, d }) => {
            show('loadingSection', false);
            scan.disabled = false;
            if (!ok) return alert('Error: ' + (d.error || 'Unknown'));

            set('resultFileName', d.filename);
            set('resultFileSize', d.filesize);
            set('resultSha256', d.sha256);
            set('predictionValue', d.prediction,
                'result-value ' + (d.prediction === 'Safe' ? 'text-success' : 'text-danger'));
            set('confidenceValue', d.confidence);
            const bar = document.getElementById('confidenceBar');
            if (bar) bar.style.width = d.confidence + '%';
            applyRiskLevels(d.risk_level);
            set('recommendationText', d.recommendation);
            const list = document.getElementById('recommendationList');
            if (list) list.innerHTML = '';
            show('resultsSection', true);
        })
        .catch(e => {
            console.error(e);
            show('loadingSection', false);
            scan.disabled = false;
            alert('Server error');
        });
    });

    const again = document.getElementById('scanAgainBtn');
    if (again) again.addEventListener('click', () => {
        file = null;
        if (input) input.value = '';
        show('fileCard', false);
        show('resultsSection', false);
        if (scan) scan.disabled = true;
    });
}