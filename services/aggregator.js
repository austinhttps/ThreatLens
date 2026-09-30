const { getGeolocation } = require('./geoService');
const { checkAbuseIPDB } = require('./abuseService');
const { checkVirusTotal } = require('./virusTotalService');

/**
 * Aggregates OSINT intelligence across multiple providers and computes a normalized Risk Score
 */

async function aggregateThreatIntel(targetInfo) {
  const startTime = Date.now();
  const { sanitized, type, subType } = targetInfo;

  // 1. First trigger Geolocation (which also resolves IP if target is a domain)
  const geoResultPromise = getGeolocation(sanitized, type);
  
  // We can fetch VirusTotal concurrently right away
  const vtResultPromise = checkVirusTotal(sanitized, type, subType);

  // Await Geo first to see if domain resolved to an IP for AbuseIPDB
  const geoResult = await geoResultPromise;
  const resolvedIp = geoResult?.data?.resolvedIp || (type === 'ip' ? sanitized : null);

  // Now query AbuseIPDB with the target/resolved IP
  const abuseResult = await checkAbuseIPDB(sanitized, type, resolvedIp);
  const vtResult = await vtResultPromise;

  const durationMs = Date.now() - startTime;

  // 2. Compute Overall Risk Score (0-100) & Threat Verdict
  const { riskScore, threatLevel, confidence, threatIndicators } = calculateRiskScore({
    type,
    geoResult,
    abuseResult,
    vtResult
  });

  return {
    target: sanitized,
    originalInput: targetInfo.original,
    type: type,
    subType: subType,
    scannedAt: new Date().toISOString(),
    durationMs: durationMs,
    overallRisk: {
      score: riskScore, // 0 - 100
      level: threatLevel, // 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS'
      confidence: confidence, // 'LOW' | 'MEDIUM' | 'HIGH'
      indicators: threatIndicators
    },
    providers: {
      geolocation: geoResult,
      abuseIPDB: abuseResult,
      virusTotal: vtResult
    }
  };
}

function calculateRiskScore({ type, geoResult, abuseResult, vtResult }) {
  let score = 0;
  const threatIndicators = [];
  let signalsCount = 0;

  // 1. VirusTotal Signals
  const vtData = vtResult?.data;
  if (vtData && vtData.lastAnalysisStats) {
    const malicious = vtData.lastAnalysisStats.malicious || 0;
    const suspicious = vtData.lastAnalysisStats.suspicious || 0;
    const total = vtData.totalEngines || 70;

    const vtMaliciousRatio = malicious / total;
    const vtSuspiciousRatio = suspicious / total;

    if (type === 'hash') {
      // For hashes, VirusTotal is the primary authority
      if (malicious > 0) {
        score = Math.min(100, Math.round((malicious / Math.max(1, total - 10)) * 100) + (suspicious * 3));
      }
    } else {
      // For IPs and Domains, scale malicious detections
      if (malicious >= 10) {
        score += 55;
      } else if (malicious >= 3) {
        score += 35;
      } else if (malicious >= 1) {
        score += 20;
      }

      if (suspicious > 0) {
        score += Math.min(15, suspicious * 4);
      }
    }

    if (malicious > 0) {
      threatIndicators.push(`${malicious}/${total} Security Vendors flagged this ${type.toUpperCase()} as Malicious`);
      signalsCount++;
    }
    if (suspicious > 0) {
      threatIndicators.push(`${suspicious} Security Vendors flagged suspicious activity`);
    }
    if (vtData.tags && vtData.tags.length > 0) {
      const maliciousTags = vtData.tags.filter(t => ['c2', 'trojan', 'ransomware', 'malware', 'botnet', 'phishing'].includes(t.toLowerCase()));
      if (maliciousTags.length > 0) {
        threatIndicators.push(`IOC Classified with high-risk tags: ${maliciousTags.join(', ')}`);
        score = Math.max(score, 70);
      }
    }
  }

  // 2. AbuseIPDB Signals (IPs and Domains)
  const abuseData = abuseResult?.data;
  if (abuseData && abuseData.abuseConfidenceScore !== undefined) {
    const abuseScore = abuseData.abuseConfidenceScore;
    const totalReports = abuseData.totalReports || 0;

    if (abuseData.isWhitelisted) {
      score = Math.max(0, score - 20);
      threatIndicators.push('Verified benign infrastructure (Whitelisted in AbuseIPDB)');
    } else {
      if (abuseScore > 0) {
        score = Math.max(score, Math.round((score * 0.4) + (abuseScore * 0.6)));
        signalsCount++;
      }

      if (totalReports > 0) {
        threatIndicators.push(`Reported ${totalReports} times across ${abuseData.numDistinctUsers || 1} distinct security reporting sources`);
      }
      if (abuseScore >= 50) {
        threatIndicators.push(`AbuseIPDB Confidence of Abuse is elevated at ${abuseScore}%`);
      }
    }
  }

  // 3. Normalize score into 0-100 bounds
  score = Math.max(0, Math.min(100, Math.round(score)));

  // 4. Determine Threat Level Verdict
  let threatLevel = 'CLEAN';
  if (score >= 60) {
    threatLevel = 'MALICIOUS';
  } else if (score >= 20) {
    threatLevel = 'SUSPICIOUS';
  } else {
    threatLevel = 'CLEAN';
  }

  // 5. Determine Confidence Level
  let confidence = 'HIGH';
  if (type === 'hash') {
    confidence = vtData ? 'HIGH' : 'LOW';
  } else {
    if (signalsCount >= 2) confidence = 'HIGH';
    else if (signalsCount === 1) confidence = 'MEDIUM';
    else confidence = 'HIGH'; // Clean with all providers reporting clean
  }

  if (threatIndicators.length === 0) {
    threatIndicators.push('No malicious telemetry or abuse reports detected across queried intelligence sources.');
  }

  return {
    riskScore: score,
    threatLevel: threatLevel,
    confidence: confidence,
    threatIndicators: threatIndicators
  };
}

module.exports = {
  aggregateThreatIntel
};
