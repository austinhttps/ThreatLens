const axios = require('axios');

/**
 * VirusTotal v3 Threat Intelligence Service
 * Endpoints:
 * - IP: https://www.virustotal.com/api/v3/ip_addresses/{ip}
 * - Domain: https://www.virustotal.com/api/v3/domains/{domain}
 * - File Hash: https://www.virustotal.com/api/v3/files/{hash}
 */

async function checkVirusTotal(target, type, subType) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY ? process.env.VIRUSTOTAL_API_KEY.trim() : '';

  let endpointCategory = 'ip_addresses';
  if (type === 'domain') {
    endpointCategory = 'domains';
  } else if (type === 'hash') {
    endpointCategory = 'files';
  }

  // If no API key configured, return realistic mock data
  if (!apiKey) {
    return generateMockVTData(target, type, subType, 'No API key provided in environment variables');
  }

  try {
    const url = `https://www.virustotal.com/api/v3/${endpointCategory}/${encodeURIComponent(target)}`;
    const response = await axios.get(url, {
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json'
      },
      timeout: 8000
    });

    if (response.data && response.data.data) {
      const attr = response.data.data.attributes || {};
      const lastStats = attr.last_analysis_stats || {
        malicious: 0,
        suspicious: 0,
        undetected: 0,
        harmless: 0,
        timeout: 0
      };

      const totalEngines = Object.values(lastStats).reduce((a, b) => a + b, 0);

      // Extract vendor details for top engines
      const engineResults = [];
      if (attr.last_analysis_results) {
        for (const [engineName, res] of Object.entries(attr.last_analysis_results)) {
          if (res.category === 'malicious' || res.category === 'suspicious' || engineResults.length < 12) {
            engineResults.push({
              engine: engineName,
              category: res.category, // 'malicious' | 'suspicious' | 'harmless' | 'undetected'
              result: res.result || 'clean',
              method: res.method || 'blacklist'
            });
          }
        }
      }

      return {
        status: 'success',
        provider: 'VirusTotal (Live API v3)',
        isMock: false,
        data: {
          target: target,
          type: type,
          subType: subType,
          reputation: attr.reputation || 0,
          lastAnalysisStats: lastStats,
          totalEngines: totalEngines || 70,
          detectionRatio: `${lastStats.malicious}/${totalEngines || 70}`,
          lastAnalysisDate: attr.last_analysis_date ? new Date(attr.last_analysis_date * 1000).toISOString() : null,
          tags: attr.tags || [],
          popularThreatClassification: attr.popular_threat_classification || null,
          categories: attr.categories || {},
          meaningfulName: attr.meaningful_name || attr.meaningful_names?.[0] || null,
          signatureInfo: attr.signature_info || null,
          engineResults: engineResults.slice(0, 16)
        }
      };
    } else {
      throw new Error('Malformed response received from VirusTotal');
    }
  } catch (err) {
    if (err.response && err.response.status === 404) {
      // 404 means the target is not currently known to VirusTotal database (e.g. fresh/unseen IOC)
      return {
        status: 'success',
        provider: 'VirusTotal (Live API v3)',
        isMock: false,
        data: {
          target: target,
          type: type,
          subType: subType,
          reputation: 0,
          lastAnalysisStats: {
            malicious: 0,
            suspicious: 0,
            undetected: 70,
            harmless: 0,
            timeout: 0
          },
          totalEngines: 70,
          detectionRatio: '0/70',
          lastAnalysisDate: null,
          tags: ['unseen-target', 'no-malware-records'],
          popularThreatClassification: null,
          categories: {},
          meaningfulName: null,
          signatureInfo: null,
          engineResults: []
        }
      };
    }
    console.warn(`[VirusTotal] Live API call failed: ${err.message}. Falling back to Demo/Mock Mode.`);
    return generateMockVTData(target, type, subType, `API error (${err.response?.status || err.message})`);
  }
}

function generateMockVTData(target, type, subType, reason) {
  // Deterministic calculation for consistent testing
  const knownMalicious = [
    '185.220.101.5',
    '45.154.255.88',
    'evil-malware-payload.top',
    'c2-beacon-command.biz',
    '44d88612fea8a8f36de82e1278abb02f', // EICAR Standard Anti-Virus Test File
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f' // WannaCry hash
  ];

  const knownBenign = [
    '8.8.8.8',
    '1.1.1.1',
    'google.com',
    'github.com',
    'microsoft.com'
  ];

  let maliciousCount = 0;
  let suspiciousCount = 0;
  let harmlessCount = 65;
  let undetectedCount = 5;
  let reputation = 0;
  let tags = [];

  const charHash = target.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);

  if (knownBenign.includes(target.toLowerCase())) {
    maliciousCount = 0;
    suspiciousCount = 0;
    harmlessCount = 68;
    undetectedCount = 2;
    reputation = 50;
    tags = ['benign', 'verified-cdn', 'trusted-resolver'];
  } else if (knownMalicious.includes(target.toLowerCase())) {
    maliciousCount = 54;
    suspiciousCount = 4;
    harmlessCount = 3;
    undetectedCount = 9;
    reputation = -85;
    tags = ['trojan', 'c2-server', 'ransomware-dropper', 'phishing'];
  } else {
    // Generate deterministic values based on charHash
    if (charHash % 3 === 0) {
      // Malicious IOC
      maliciousCount = 38 + (charHash % 25);
      suspiciousCount = 3 + (charHash % 5);
      harmlessCount = 5;
      undetectedCount = 70 - maliciousCount - suspiciousCount - harmlessCount;
      reputation = -50 - (charHash % 40);
      tags = type === 'hash' ? ['malware', 'trojan.win32', 'backdoor'] : ['c2', 'botnet', 'malicious-activity'];
    } else if (charHash % 3 === 1) {
      // Suspicious IOC
      maliciousCount = 4 + (charHash % 8);
      suspiciousCount = 3 + (charHash % 4);
      harmlessCount = 42;
      undetectedCount = 70 - maliciousCount - suspiciousCount - harmlessCount;
      reputation = -15;
      tags = ['suspicious-traffic', 'newly-registered-domain'];
    } else {
      // Clean IOC
      maliciousCount = 0;
      suspiciousCount = 0;
      harmlessCount = 64 + (charHash % 5);
      undetectedCount = 70 - harmlessCount;
      reputation = 20;
      tags = ['clean', 'no-threats-detected'];
    }
  }

  const standardVendors = [
    'Kaspersky', 'CrowdStrike Falcon', 'Microsoft Defender', 'Sophos', 
    'BitDefender', 'Symantec', 'TrendMicro', 'Fortinet', 
    'SentinelOne', 'Palo Alto Networks', 'ESET-NOD32', 'Avast-AVG'
  ];

  const engineResults = standardVendors.map((vendor, index) => {
    let category = 'harmless';
    let result = 'clean';

    if (maliciousCount > 0 && index < (maliciousCount / 5)) {
      category = 'malicious';
      result = type === 'hash' ? 'Trojan:Win32/Agent.Tesla' : 'Malicious / Command-and-Control';
    } else if (suspiciousCount > 0 && index === 0) {
      category = 'suspicious';
      result = 'Unwanted Software / Riskware';
    }

    return {
      engine: vendor,
      category: category,
      result: result,
      method: 'blacklist'
    };
  });

  return {
    status: 'success',
    provider: 'VirusTotal [Demo/Mock Mode]',
    isMock: true,
    mockReason: reason,
    data: {
      target: target,
      type: type,
      subType: subType,
      reputation: reputation,
      lastAnalysisStats: {
        malicious: maliciousCount,
        suspicious: suspiciousCount,
        harmless: harmlessCount,
        undetected: undetectedCount,
        timeout: 0
      },
      totalEngines: 70,
      detectionRatio: `${maliciousCount}/70`,
      lastAnalysisDate: new Date(Date.now() - 3600000 * 2).toISOString(),
      tags: tags,
      popularThreatClassification: maliciousCount > 0 ? {
        suggested_threat_label: type === 'hash' ? 'trojan.agent/stealer' : 'c2.malicious_infra',
        popular_threat_category: [{ count: maliciousCount, value: 'trojan' }]
      } : null,
      meaningfulName: type === 'hash' ? 'payload_win64_dropped.exe' : null,
      engineResults: engineResults
    }
  };
}

module.exports = {
  checkVirusTotal
};
