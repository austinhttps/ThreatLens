/**
 * ThreatLens OSINT & Threat Intelligence Frontend Logic
 */

document.addEventListener('DOMContentLoaded', () => {
  // Initialize Lucide Icons
  if (window.lucide) {
    window.lucide.createIcons();
  }

  // DOM Elements
  const lookupForm = document.getElementById('lookupForm');
  const targetInput = document.getElementById('targetInput');
  const submitBtn = document.getElementById('submitBtn');
  const detectedBadge = document.getElementById('detectedBadge');
  const refangNotice = document.getElementById('refangNotice');
  const scannerLoader = document.getElementById('scannerLoader');
  const scanningStage = document.getElementById('scanningStage');
  const errorBanner = document.getElementById('errorBanner');
  const errorMessage = document.getElementById('errorMessage');
  const resultsSection = document.getElementById('resultsSection');

  // Summary Elements
  const resultTypeBadge = document.getElementById('resultTypeBadge');
  const resultTarget = document.getElementById('resultTarget');
  const verdictBadge = document.getElementById('verdictBadge');
  const verdictText = document.getElementById('verdictText');
  const confidenceText = document.getElementById('confidenceText');
  const cacheBadge = document.getElementById('cacheBadge');
  const cacheText = document.getElementById('cacheText');
  const indicatorsList = document.getElementById('indicatorsList');
  const overallScoreNumber = document.getElementById('overallScoreNumber');
  const scoreProgressCircle = document.getElementById('scoreProgressCircle');
  const scanDurationText = document.getElementById('scanDurationText');
  const scanTimestampText = document.getElementById('scanTimestampText');
  const copyTargetBtn = document.getElementById('copyTargetBtn');
  const copySummaryBtn = document.getElementById('copySummaryBtn');
  const exportJsonBtn = document.getElementById('exportJsonBtn');

  // Intel Grid Elements - Geo
  const geoProviderBadge = document.getElementById('geoProviderBadge');
  const geoDetails = document.getElementById('geoDetails');
  const geoNotApplicable = document.getElementById('geoNotApplicable');
  const mapWrapper = document.getElementById('mapWrapper');
  const geoFlag = document.getElementById('geoFlag');
  const geoCountryText = document.getElementById('geoCountryText');
  const geoCityCoords = document.getElementById('geoCityCoords');
  const geoIsp = document.getElementById('geoIsp');
  const geoAsn = document.getElementById('geoAsn');
  const geoReverseDns = document.getElementById('geoReverseDns');
  const geoTimezone = document.getElementById('geoTimezone');

  // Intel Grid Elements - AbuseIPDB
  const abuseProviderBadge = document.getElementById('abuseProviderBadge');
  const abuseDetails = document.getElementById('abuseDetails');
  const abuseNotApplicable = document.getElementById('abuseNotApplicable');
  const abuseScoreVal = document.getElementById('abuseScoreVal');
  const abuseScoreBar = document.getElementById('abuseScoreBar');
  const abuseTotalReports = document.getElementById('abuseTotalReports');
  const abuseDistinctUsers = document.getElementById('abuseDistinctUsers');
  const abuseUsageType = document.getElementById('abuseUsageType');
  const abuseDomain = document.getElementById('abuseDomain');
  const abuseLastReported = document.getElementById('abuseLastReported');
  const abuseWhitelisted = document.getElementById('abuseWhitelisted');
  const abuseReportsList = document.getElementById('abuseReportsList');

  // Intel Grid Elements - VirusTotal
  const vtProviderBadge = document.getElementById('vtProviderBadge');
  const vtRatioText = document.getElementById('vtRatioText');
  const vtMaliciousBar = document.getElementById('vtMaliciousBar');
  const vtSuspiciousBar = document.getElementById('vtSuspiciousBar');
  const vtHarmlessBar = document.getElementById('vtHarmlessBar');
  const vtUndetectedBar = document.getElementById('vtUndetectedBar');
  const vtMaliciousCount = document.getElementById('vtMaliciousCount');
  const vtSuspiciousCount = document.getElementById('vtSuspiciousCount');
  const vtHarmlessCount = document.getElementById('vtHarmlessCount');
  const vtThreatLabel = document.getElementById('vtThreatLabel');
  const vtReputation = document.getElementById('vtReputation');
  const vtTagsList = document.getElementById('vtTagsList');
  const vtEngineList = document.getElementById('vtEngineList');

  // History & Health
  const historyContainer = document.getElementById('historyContainer');
  const emptyHistoryMsg = document.getElementById('emptyHistoryMsg');
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');
  const healthBtn = document.getElementById('healthBtn');
  const apiStatusBtn = document.getElementById('apiStatusBtn');
  const healthModal = document.getElementById('healthModal');
  const closeHealthModal = document.getElementById('closeHealthModal');
  const healthModalBody = document.getElementById('healthModalBody');

  let currentReportData = null;
  let leafletMap = null;
  let scanStageInterval = null;

  // ----------------------------------------------------
  // CLIENT-SIDE TARGET DETECTION
  // ----------------------------------------------------

  function refangPreview(str) {
    if (!str) return '';
    return str
      .replace(/^hxxps?:\/\//i, '')
      .replace(/^https?:\/\//i, '')
      .replace(/\[\.\]/g, '.')
      .replace(/\(\.\)/g, '.')
      .replace(/\[:\]/g, ':')
      .split('/')[0]
      .trim();
  }

  function detectTargetType(raw) {
    const sanitized = refangPreview(raw);
    if (!sanitized) return { type: 'none', label: 'Waiting for input...' };

    // IPv4
    const ipv4Regex = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
    if (ipv4Regex.test(sanitized)) {
      return { type: 'ip', label: 'Detected: IPv4 Address', color: 'bg-cyan-950 text-cyan-400 border-cyan-700' };
    }

    // SHA-256
    if (/^[a-fA-F0-9]{64}$/.test(sanitized)) {
      return { type: 'hash', label: 'Detected: SHA-256 Hash', color: 'bg-amber-950 text-amber-400 border-amber-700' };
    }

    // SHA-1
    if (/^[a-fA-F0-9]{40}$/.test(sanitized)) {
      return { type: 'hash', label: 'Detected: SHA-1 Hash', color: 'bg-amber-950 text-amber-400 border-amber-700' };
    }

    // MD5
    if (/^[a-fA-F0-9]{32}$/.test(sanitized)) {
      return { type: 'hash', label: 'Detected: MD5 Hash', color: 'bg-purple-950 text-purple-400 border-purple-700' };
    }

    // Domain
    const domainRegex = /^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.[a-zA-Z]{2,63}$/;
    if (domainRegex.test(sanitized)) {
      return { type: 'domain', label: 'Detected: Domain Name', color: 'bg-emerald-950 text-emerald-400 border-emerald-700' };
    }

    return { type: 'unknown', label: 'Format: Unknown / Typing...', color: 'bg-slate-800 text-slate-400 border-slate-700' };
  }

  targetInput.addEventListener('input', () => {
    const raw = targetInput.value.trim();
    const detection = detectTargetType(raw);

    // Show refang alert if brackets/hxxp detected
    if (raw.includes('[.]') || raw.includes('hxxp') || raw.includes('[:]')) {
      refangNotice.classList.remove('hidden');
    } else {
      refangNotice.classList.add('hidden');
    }

    detectedBadge.textContent = detection.label;
    detectedBadge.className = `text-xs px-2.5 py-1 rounded font-mono-code font-medium border transition-all ${detection.color || 'bg-slate-800 text-slate-400 border-slate-700'}`;
  });

  // Sample Buttons Click
  document.querySelectorAll('.sample-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const sample = btn.getAttribute('data-sample');
      targetInput.value = sample;
      targetInput.dispatchEvent(new Event('input'));
      performLookup(sample);
    });
  });

  // Form Submit
  lookupForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const target = targetInput.value.trim();
    if (target) {
      performLookup(target);
    }
  });

  // ----------------------------------------------------
  // PERFORM LOOKUP API CALL
  // ----------------------------------------------------

  async function performLookup(target) {
    // UI state reset
    errorBanner.classList.add('hidden');
    resultsSection.classList.add('hidden');
    scannerLoader.classList.remove('hidden');
    submitBtn.disabled = true;

    // Animated status stages
    const stages = [
      'Normalizing target IOC and validating syntax...',
      'Querying IP Geolocation & Autonomous System Number (IP-API)...',
      'Auditing historical abuse reports & threat confidence (AbuseIPDB)...',
      'Correlating multi-engine detection verdicts & threat tags (VirusTotal v3)...',
      'Synthesizing composite risk score & computing verdict...'
    ];
    let stageIdx = 0;
    scanningStage.textContent = stages[0];
    clearInterval(scanStageInterval);
    scanStageInterval = setInterval(() => {
      stageIdx = (stageIdx + 1) % stages.length;
      scanningStage.textContent = stages[stageIdx];
    }, 650);

    try {
      const response = await fetch('/api/lookup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ target: target })
      });

      const json = await response.json();
      clearInterval(scanStageInterval);

      if (!response.ok || !json.success) {
        throw new Error(json.error || 'Failed to aggregate threat intelligence');
      }

      currentReportData = json;
      renderResults(json);
      saveToHistory(json.data);

    } catch (err) {
      clearInterval(scanStageInterval);
      showError(err.message);
    } finally {
      scannerLoader.classList.add('hidden');
      submitBtn.disabled = false;
      if (window.lucide) window.lucide.createIcons();
    }
  }

  function showError(msg) {
    errorMessage.textContent = msg;
    errorBanner.classList.remove('hidden');
    resultsSection.classList.add('hidden');
  }

  // ----------------------------------------------------
  // RENDER REPORT RESULTS
  // ----------------------------------------------------

  function renderResults(apiResponse) {
    const report = apiResponse.data;
    const isCached = apiResponse.cached;
    const expiresAt = apiResponse.cacheExpiresAt;

    resultsSection.classList.remove('hidden');

    // 1. Summary Header
    resultTypeBadge.textContent = report.subType.toUpperCase();
    resultTarget.textContent = report.target;

    // Cache Badge
    if (isCached) {
      cacheBadge.className = 'text-xs font-mono-code text-cyan-300 flex items-center gap-1.5 bg-cyan-950/60 px-3 py-1.5 rounded border border-cyan-700';
      cacheText.textContent = '⚡ CACHED (15M TTL)';
    } else {
      cacheBadge.className = 'text-xs font-mono-code text-emerald-400 flex items-center gap-1.5 bg-emerald-950/60 px-3 py-1.5 rounded border border-emerald-700';
      cacheText.textContent = '🌐 LIVE SCAN';
    }

    // Verdict Badge & Colors
    const risk = report.overallRisk;
    const score = risk.score;

    if (risk.level === 'MALICIOUS') {
      verdictBadge.className = 'px-4 py-1.5 rounded-md font-mono-code font-bold text-sm uppercase tracking-wider flex items-center gap-2 bg-rose-950/80 text-rose-300 border border-rose-700/80 shadow-lg shadow-rose-900/20';
      verdictText.textContent = 'MALICIOUS THREAT';
      scoreProgressCircle.setAttribute('stroke', '#f43f5e'); // Rose
    } else if (risk.level === 'SUSPICIOUS') {
      verdictBadge.className = 'px-4 py-1.5 rounded-md font-mono-code font-bold text-sm uppercase tracking-wider flex items-center gap-2 bg-amber-950/80 text-amber-300 border border-amber-700/80 shadow-lg shadow-amber-900/20';
      verdictText.textContent = 'SUSPICIOUS ACTIVITY';
      scoreProgressCircle.setAttribute('stroke', '#f59e0b'); // Amber
    } else {
      verdictBadge.className = 'px-4 py-1.5 rounded-md font-mono-code font-bold text-sm uppercase tracking-wider flex items-center gap-2 bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 shadow-lg shadow-emerald-900/20';
      verdictText.textContent = 'CLEAN / BENIGN';
      scoreProgressCircle.setAttribute('stroke', '#10b981'); // Emerald
    }

    confidenceText.textContent = risk.confidence;
    overallScoreNumber.textContent = score;

    // SVG Radial Score Meter Animation
    // Circumference for r=38 is 2 * PI * 38 = 238.76
    const circumference = 238.76;
    const offset = circumference - (score / 100) * circumference;
    setTimeout(() => {
      scoreProgressCircle.style.strokeDashoffset = offset;
    }, 100);

    // Threat Indicators List
    indicatorsList.innerHTML = '';
    (risk.indicators || []).forEach(ind => {
      const li = document.createElement('li');
      li.className = 'flex items-start gap-1.5';
      li.innerHTML = `<span class="text-cyan-400 mt-0.5">›</span><span>${escapeHtml(ind)}</span>`;
      indicatorsList.appendChild(li);
    });

    scanDurationText.textContent = `${report.durationMs}ms`;
    scanTimestampText.textContent = new Date(report.scannedAt).toLocaleTimeString();

    // 2. Geolocation Card
    renderGeoCard(report.providers.geolocation, report.type);

    // 3. AbuseIPDB Card
    renderAbuseCard(report.providers.abuseIPDB, report.type);

    // 4. VirusTotal Card
    renderVirusTotalCard(report.providers.virusTotal);

    // Smooth Scroll into Results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ----------------------------------------------------
  // CARD RENDERERS
  // ----------------------------------------------------

  function renderGeoCard(geo, targetType) {
    if (targetType === 'hash' || !geo || geo.status === 'not_applicable') {
      geoDetails.classList.add('hidden');
      mapWrapper.classList.add('hidden');
      geoNotApplicable.classList.remove('hidden');
      geoProviderBadge.textContent = 'N/A';
      return;
    }

    geoNotApplicable.classList.add('hidden');
    geoDetails.classList.remove('hidden');
    mapWrapper.classList.remove('hidden');
    geoProviderBadge.textContent = geo.provider || 'IP-API';

    const d = geo.data;
    if (d) {
      geoFlag.textContent = getFlagEmoji(d.countryCode);
      geoCountryText.textContent = `${d.country} (${d.countryCode})`;
      geoCityCoords.textContent = `${d.city}, ${d.regionName} (${d.lat.toFixed(2)}, ${d.lon.toFixed(2)})`;
      geoIsp.textContent = d.isp || 'N/A';
      geoAsn.textContent = d.asn || 'N/A';
      geoReverseDns.textContent = d.reverseDns || 'N/A';
      geoTimezone.textContent = d.timezone || 'UTC';

      // Render or Update Leaflet Map
      renderLeafletMap(d.lat, d.lon, `${d.city}, ${d.country} (${d.query})`);
    }
  }

  function renderLeafletMap(lat, lon, label) {
    if (!lat || !lon) return;

    if (!leafletMap) {
      leafletMap = L.map('mapContainer', {
        center: [lat, lon],
        zoom: 5,
        attributionControl: true,
        zoomControl: true,
        scrollWheelZoom: false
      });

      // OSM Tile Policy compliant endpoint & attribution
      L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors | <a href="https://www.openstreetmap.org/fixthemap" target="_blank" rel="noopener noreferrer">Fix the map</a>'
      }).addTo(leafletMap);
    } else {
      leafletMap.setView([lat, lon], 5);
      leafletMap.eachLayer(layer => {
        if (layer instanceof L.Marker) leafletMap.removeLayer(layer);
      });
    }

    // Custom Glowing Cyber Marker
    const cyberIcon = L.divIcon({
      className: 'custom-cyber-marker',
      html: `<div class="w-4 h-4 rounded-full bg-cyan-400 border-2 border-slate-950 shadow-lg shadow-cyan-400/80 status-beacon"></div>`,
      iconSize: [16, 16],
      iconAnchor: [8, 8]
    });

    L.marker([lat, lon], { icon: cyberIcon }).addTo(leafletMap)
      .bindPopup(`<div class="p-1 font-mono-code text-xs"><b>Target Geolocation:</b><br/>${escapeHtml(label)}</div>`)
      .openPopup();

    setTimeout(() => {
      leafletMap.invalidateSize();
    }, 200);
  }

  function renderAbuseCard(abuse, targetType) {
    if (targetType === 'hash' || !abuse || abuse.status === 'not_applicable') {
      abuseDetails.classList.add('hidden');
      abuseNotApplicable.classList.remove('hidden');
      abuseProviderBadge.textContent = 'N/A';
      return;
    }

    abuseNotApplicable.classList.add('hidden');
    abuseDetails.classList.remove('hidden');
    abuseProviderBadge.textContent = abuse.provider || 'AbuseIPDB';

    const d = abuse.data;
    if (d) {
      const score = d.abuseConfidenceScore || 0;
      abuseScoreVal.textContent = `${score}%`;
      abuseScoreBar.style.width = `${score}%`;

      if (score >= 60) {
        abuseScoreVal.className = 'text-base font-bold text-rose-400';
        abuseScoreBar.className = 'bg-rose-500 h-2 rounded-full transition-all duration-500';
      } else if (score >= 20) {
        abuseScoreVal.className = 'text-base font-bold text-amber-400';
        abuseScoreBar.className = 'bg-amber-400 h-2 rounded-full transition-all duration-500';
      } else {
        abuseScoreVal.className = 'text-base font-bold text-emerald-400';
        abuseScoreBar.className = 'bg-emerald-400 h-2 rounded-full transition-all duration-500';
      }

      abuseTotalReports.textContent = (d.totalReports || 0).toLocaleString();
      abuseDistinctUsers.textContent = (d.numDistinctUsers || 0).toLocaleString();
      abuseUsageType.textContent = d.usageType || 'N/A';
      abuseDomain.textContent = d.domain || d.hostnames?.[0] || 'N/A';
      abuseWhitelisted.textContent = d.isWhitelisted ? 'Yes (Verified Safe)' : 'No';
      abuseWhitelisted.className = d.isWhitelisted ? 'text-emerald-400 font-semibold text-right' : 'text-slate-300 text-right';

      if (d.lastReportedAt) {
        abuseLastReported.textContent = formatTimeAgo(new Date(d.lastReportedAt));
      } else {
        abuseLastReported.textContent = 'No recent reports';
      }

      // Abuse Reports Snippets
      abuseReportsList.innerHTML = '';
      if (d.reports && d.reports.length > 0) {
        d.reports.forEach(r => {
          const item = document.createElement('div');
          item.className = 'bg-slate-900/60 p-2 rounded border border-slate-800 text-[11px] space-y-1';
          item.innerHTML = `
            <div class="text-slate-300 line-clamp-2">"${escapeHtml(r.comment || 'Suspicious traffic reported')}"</div>
            <div class="text-[10px] text-slate-500 flex justify-between">
              <span>Reporter #${r.reporterId || 'Anon'}</span>
              <span>${formatTimeAgo(new Date(r.reportedAt))}</span>
            </div>
          `;
          abuseReportsList.appendChild(item);
        });
      } else {
        abuseReportsList.innerHTML = '<p class="text-[11px] text-slate-500 italic">No individual incident reports filed.</p>';
      }
    }
  }

  function renderVirusTotalCard(vt) {
    if (!vt || !vt.data) return;

    vtProviderBadge.textContent = vt.provider || 'VirusTotal v3';
    const d = vt.data;
    const stats = d.lastAnalysisStats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 };
    const total = d.totalEngines || 70;

    vtRatioText.textContent = `${stats.malicious} / ${total} Vendors`;
    vtRatioText.className = stats.malicious > 0 ? 'text-sm font-bold text-rose-400' : 'text-sm font-bold text-emerald-400';

    // Segmented progress bar widths %
    const mPct = (stats.malicious / total) * 100;
    const sPct = (stats.suspicious / total) * 100;
    const hPct = (stats.harmless / total) * 100;
    const uPct = 100 - mPct - sPct - hPct;

    vtMaliciousBar.style.width = `${mPct}%`;
    vtSuspiciousBar.style.width = `${sPct}%`;
    vtHarmlessBar.style.width = `${hPct}%`;
    vtUndetectedBar.style.width = `${Math.max(0, uPct)}%`;

    vtMaliciousCount.textContent = stats.malicious;
    vtSuspiciousCount.textContent = stats.suspicious;
    vtHarmlessCount.textContent = stats.harmless;

    vtThreatLabel.textContent = d.popularThreatClassification?.suggested_threat_label || d.meaningfulName || (stats.malicious > 0 ? 'trojan.detected' : 'clean.ioc');
    vtReputation.textContent = d.reputation !== undefined ? d.reputation : '0';

    // Tags
    vtTagsList.innerHTML = '';
    const tags = d.tags || [];
    if (tags.length > 0) {
      tags.forEach(tag => {
        const span = document.createElement('span');
        span.className = 'text-[10px] px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 font-mono-code';
        span.textContent = `#${tag}`;
        vtTagsList.appendChild(span);
      });
    } else {
      vtTagsList.innerHTML = '<span class="text-[10px] text-slate-500">None</span>';
    }

    // Top Engine Grid
    vtEngineList.innerHTML = '';
    const engines = d.engineResults || [];
    if (engines.length > 0) {
      engines.forEach(eng => {
        const div = document.createElement('div');
        const isMal = eng.category === 'malicious';
        const isSusp = eng.category === 'suspicious';
        
        let badgeColor = 'text-emerald-400 bg-emerald-950/40 border-emerald-800';
        let badgeText = 'Clean';
        if (isMal) {
          badgeColor = 'text-rose-400 bg-rose-950/40 border-rose-800';
          badgeText = 'Malicious';
        } else if (isSusp) {
          badgeColor = 'text-amber-400 bg-amber-950/40 border-amber-800';
          badgeText = 'Suspicious';
        }

        div.className = 'bg-slate-900/80 p-1.5 rounded border border-slate-800 flex items-center justify-between text-[10px]';
        div.innerHTML = `
          <span class="text-slate-300 truncate max-w-[90px] font-semibold">${escapeHtml(eng.engine)}</span>
          <span class="px-1.5 py-0.5 rounded border font-mono-code ${badgeColor}">${badgeText}</span>
        `;
        vtEngineList.appendChild(div);
      });
    } else {
      vtEngineList.innerHTML = '<span class="text-[11px] text-slate-500 col-span-2">Engine breakdown unavailable</span>';
    }
  }

  // ----------------------------------------------------
  // LOCAL STORAGE INVESTIGATION HISTORY
  // ----------------------------------------------------

  function saveToHistory(report) {
    if (!report || !report.target) return;

    let history = JSON.parse(localStorage.getItem('threatlens_history') || '[]');
    // Filter out duplicates
    history = history.filter(h => h.target.toLowerCase() !== report.target.toLowerCase());
    
    history.unshift({
      target: report.target,
      type: report.subType || report.type,
      score: report.overallRisk.score,
      level: report.overallRisk.level,
      timestamp: new Date().toISOString()
    });

    // Keep last 15 items
    if (history.length > 15) history.pop();
    localStorage.setItem('threatlens_history', JSON.stringify(history));
    renderHistory();
  }

  function renderHistory() {
    const history = JSON.parse(localStorage.getItem('threatlens_history') || '[]');
    if (history.length === 0) {
      emptyHistoryMsg.classList.remove('hidden');
      historyContainer.innerHTML = '';
      historyContainer.appendChild(emptyHistoryMsg);
      return;
    }

    emptyHistoryMsg.classList.add('hidden');
    historyContainer.innerHTML = '';

    history.forEach(item => {
      const row = document.createElement('div');
      row.className = 'flex items-center justify-between p-2.5 rounded-lg bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 transition-all font-mono-code text-xs';

      let scoreBadge = 'bg-emerald-950 text-emerald-400 border-emerald-800';
      if (item.level === 'MALICIOUS') {
        scoreBadge = 'bg-rose-950 text-rose-400 border-rose-800';
      } else if (item.level === 'SUSPICIOUS') {
        scoreBadge = 'bg-amber-950 text-amber-400 border-amber-800';
      }

      row.innerHTML = `
        <div class="flex items-center space-x-3 overflow-hidden">
          <span class="text-[10px] uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 flex-shrink-0">
            ${escapeHtml(item.type)}
          </span>
          <span class="font-bold text-white truncate max-w-xs sm:max-w-md">${escapeHtml(item.target)}</span>
        </div>
        
        <div class="flex items-center space-x-3 flex-shrink-0">
          <span class="px-2 py-0.5 rounded border text-[11px] font-bold ${scoreBadge}">
            ${item.score}/100
          </span>
          <span class="text-slate-500 text-[11px] hidden sm:inline">${formatTimeAgo(new Date(item.timestamp))}</span>
          <button class="history-rescan-btn text-cyan-400 hover:text-cyan-300 p-1 hover:bg-slate-700 rounded transition-colors" data-target="${escapeHtml(item.target)}" title="Re-scan Target">
            <i data-lucide="rotate-cw" class="w-3.5 h-3.5"></i>
          </button>
        </div>
      `;

      historyContainer.appendChild(row);
    });

    // Attach click handlers to re-scan buttons
    document.querySelectorAll('.history-rescan-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const t = btn.getAttribute('data-target');
        targetInput.value = t;
        targetInput.dispatchEvent(new Event('input'));
        performLookup(t);
      });
    });

    if (window.lucide) window.lucide.createIcons();
  }

  clearHistoryBtn.addEventListener('click', () => {
    localStorage.removeItem('threatlens_history');
    renderHistory();
  });

  // ----------------------------------------------------
  // EXPORT JSON & CLIPBOARD ACTIONS
  // ----------------------------------------------------

  exportJsonBtn.addEventListener('click', () => {
    if (!currentReportData) return;
    const report = currentReportData;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threatlens_report_${report.data.target.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  copyTargetBtn.addEventListener('click', () => {
    if (!currentReportData) return;
    navigator.clipboard.writeText(currentReportData.data.target);
    showToast('Target IOC copied to clipboard!');
  });

  copySummaryBtn.addEventListener('click', () => {
    if (!currentReportData) return;
    const r = currentReportData.data;
    const text = `[ThreatLens Intel Report]\nTarget: ${r.target} (${r.subType})\nVerdict: ${r.overallRisk.level} (Score: ${r.overallRisk.score}/100)\nConfidence: ${r.overallRisk.confidence}\nKey Findings:\n- ${r.overallRisk.indicators.join('\n- ')}\nScanned: ${r.scannedAt}`;
    navigator.clipboard.writeText(text);
    showToast('Threat summary copied to clipboard!');
  });

  // ----------------------------------------------------
  // SYSTEM HEALTH MODAL
  // ----------------------------------------------------

  async function fetchHealth() {
    try {
      const res = await fetch('/api/health');
      const data = await res.json();
      
      healthModalBody.innerHTML = `
        <div class="bg-slate-900 p-3 rounded border border-slate-800 space-y-2">
          <div class="flex justify-between">
            <span class="text-slate-400">Application Status:</span>
            <span class="text-emerald-400 font-bold uppercase">● Online</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">Server Uptime:</span>
            <span class="text-white">${Math.floor(data.uptimeSeconds / 60)} mins ${data.uptimeSeconds % 60}s</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">Cache Active Keys:</span>
            <span class="text-cyan-400">${data.cache.activeKeys} targets</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">Cache Hits / Misses:</span>
            <span class="text-white">${data.cache.hits} hits / ${data.cache.misses} misses</span>
          </div>
          <div class="flex justify-between">
            <span class="text-slate-400">Cache TTL:</span>
            <span class="text-white">${data.cache.ttlSeconds / 60} minutes</span>
          </div>
        </div>

        <h4 class="font-bold text-white pt-2">Intelligence Providers Status:</h4>
        <div class="space-y-1.5">
          <div class="p-2 bg-slate-900 rounded border border-slate-800 flex justify-between items-center">
            <span>IP-API Geolocation</span>
            <span class="text-emerald-400 bg-emerald-950/40 border border-emerald-800 px-2 py-0.5 rounded">Live Free Tier</span>
          </div>
          <div class="p-2 bg-slate-900 rounded border border-slate-800 flex justify-between items-center">
            <span>AbuseIPDB</span>
            <span class="${data.providers.abuseIPDB.hasKey ? 'text-emerald-400 bg-emerald-950/40 border-emerald-800' : 'text-amber-400 bg-amber-950/40 border-amber-800'} px-2 py-0.5 rounded">
              ${data.providers.abuseIPDB.hasKey ? 'Live API Key' : 'Demo / Mock Mode'}
            </span>
          </div>
          <div class="p-2 bg-slate-900 rounded border border-slate-800 flex justify-between items-center">
            <span>VirusTotal v3</span>
            <span class="${data.providers.virusTotal.hasKey ? 'text-emerald-400 bg-emerald-950/40 border-emerald-800' : 'text-amber-400 bg-amber-950/40 border-amber-800'} px-2 py-0.5 rounded">
              ${data.providers.virusTotal.hasKey ? 'Live API Key' : 'Demo / Mock Mode'}
            </span>
          </div>
        </div>
      `;
    } catch (err) {
      healthModalBody.innerHTML = `<p class="text-rose-400">Failed to connect to backend health endpoint.</p>`;
    }
  }

  healthBtn.addEventListener('click', () => {
    fetchHealth();
    healthModal.classList.remove('hidden');
  });

  apiStatusBtn.addEventListener('click', () => {
    fetchHealth();
    healthModal.classList.remove('hidden');
  });

  closeHealthModal.addEventListener('click', () => {
    healthModal.classList.add('hidden');
  });

  // ----------------------------------------------------
  // HELPERS
  // ----------------------------------------------------

  function formatTimeAgo(date) {
    const seconds = Math.floor((new Date() - date) / 1000);
    if (seconds < 60) return 'just now';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  }

  function getFlagEmoji(countryCode) {
    if (!countryCode || countryCode.length !== 2) return '🌐';
    const codePoints = countryCode
      .toUpperCase()
      .split('')
      .map(char => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function showToast(msg) {
    const toast = document.createElement('div');
    toast.className = 'fixed bottom-6 right-6 bg-cyan-950 border border-cyan-500 text-cyan-300 px-4 py-2.5 rounded-lg shadow-xl text-xs font-mono-code z-50 animate-bounce';
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, 2500);
  }

  // Initial Load
  renderHistory();
});
