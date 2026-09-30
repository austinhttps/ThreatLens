const axios = require('axios');

/**
 * AbuseIPDB Threat Intelligence Service
 * Endpoint: https://api.abuseipdb.com/api/v2/check
 */

async function checkAbuseIPDB(target, type, resolvedIp = null) {
  if (type === 'hash') {
    return {
      status: 'not_applicable',
      provider: 'AbuseIPDB',
      isMock: false,
      message: 'AbuseIPDB reputation is not applicable for file hashes.',
      data: null
    };
  }

  const queryIp = type === 'ip' ? target : resolvedIp;
  const apiKey = process.env.ABUSEIPDB_API_KEY ? process.env.ABUSEIPDB_API_KEY.trim() : '';

  if (!queryIp) {
    return generateMockAbuseData(target, 'Domain could not be mapped to an IP address for AbuseIPDB check');
  }

  // If no API key configured, return realistic mock data flagged as Demo Mode
  if (!apiKey) {
    return generateMockAbuseData(queryIp, 'No API key provided in environment variables');
  }

  try {
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: {
        ipAddress: queryIp,
        maxAgeInDays: 90,
        verbose: true
      },
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      },
      timeout: 6000
    });

    if (response.data && response.data.data) {
      const d = response.data.data;
      return {
        status: 'success',
        provider: 'AbuseIPDB (Live API)',
        isMock: false,
        data: {
          ipAddress: d.ipAddress,
          isPublic: d.isPublic,
          ipVersion: d.ipVersion,
          isWhitelisted: d.isWhitelisted,
          abuseConfidenceScore: d.abuseConfidenceScore,
          countryCode: d.countryCode,
          usageType: d.usageType || 'Commercial/Hosting',
          isp: d.isp,
          domain: d.domain,
          hostnames: d.hostnames || [],
          totalReports: d.totalReports,
          numDistinctUsers: d.numDistinctUsers,
          lastReportedAt: d.lastReportedAt || null,
          reports: (d.reports || []).slice(0, 5).map(r => ({
            reportedAt: r.reportedAt,
            comment: r.comment,
            categories: r.categories,
            reporterId: r.reporterId
          }))
        }
      };
    } else {
      throw new Error('Unexpected response format from AbuseIPDB');
    }
  } catch (err) {
    console.warn(`[AbuseIPDB] Live API check failed: ${err.message}. Falling back to Demo/Mock Mode.`);
    return generateMockAbuseData(queryIp, `API request failed (${err.response?.status || err.message})`);
  }
}

function generateMockAbuseData(ip, reason) {
  // Check known demo IPs for tailored realistic demo results
  const knownMalicious = ['185.220.101.5', '45.154.255.88', '194.26.29.112', '198.51.100.1'];
  const knownBenign = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '142.250.190.46'];

  let score = 0;
  let totalReports = 0;
  let distinctUsers = 0;
  let lastReported = null;
  let isWhitelisted = false;

  if (knownBenign.includes(ip)) {
    score = 0;
    totalReports = 0;
    distinctUsers = 0;
    isWhitelisted = true;
  } else if (knownMalicious.includes(ip)) {
    score = 88;
    totalReports = 342;
    distinctUsers = 84;
    lastReported = new Date(Date.now() - 3600000 * 4).toISOString();
  } else {
    // Generate deterministic demo score based on IP characters
    const hash = ip.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
    if (hash % 3 === 0) {
      score = 75 + (hash % 25);
      totalReports = 45 + (hash % 200);
      distinctUsers = 12 + (hash % 40);
      lastReported = new Date(Date.now() - (hash % 48) * 3600000).toISOString();
    } else if (hash % 3 === 1) {
      score = 25 + (hash % 20);
      totalReports = 4 + (hash % 10);
      distinctUsers = 2 + (hash % 4);
      lastReported = new Date(Date.now() - 86400000 * 12).toISOString();
    } else {
      score = 0;
      totalReports = 0;
      distinctUsers = 0;
      isWhitelisted = false;
    }
  }

  const mockCategories = [
    { id: 18, name: 'Brute-Force' },
    { id: 14, name: 'Port Scan' },
    { id: 22, name: 'SSH Attack' },
    { id: 15, name: 'Hacking / Exploit' },
    { id: 4, name: 'DDoS Attack' }
  ];

  const sampleReports = totalReports > 0 ? [
    {
      reportedAt: lastReported || new Date().toISOString(),
      comment: 'SSH brute force attacks detected repeatedly targeting port 22.',
      categories: [18, 22],
      reporterId: 1042
    },
    {
      reportedAt: new Date(Date.now() - 86400000 * 2).toISOString(),
      comment: 'Automated vulnerability scanning probing for exposed API credentials and .env paths.',
      categories: [14, 15],
      reporterId: 8871
    }
  ] : [];

  return {
    status: 'success',
    provider: 'AbuseIPDB [Demo/Mock Mode]',
    isMock: true,
    mockReason: reason,
    data: {
      ipAddress: ip,
      isPublic: true,
      ipVersion: 4,
      isWhitelisted: isWhitelisted,
      abuseConfidenceScore: score,
      countryCode: 'US',
      usageType: score > 50 ? 'Data Center / Web Hosting / Transit' : 'Commercial / ISP',
      isp: 'Cloud Infrastructure Provider',
      domain: 'network-provider.net',
      hostnames: [`host-${ip.replace(/\./g, '-')}.nodes.net`],
      totalReports: totalReports,
      numDistinctUsers: distinctUsers,
      lastReportedAt: lastReported,
      reports: sampleReports
    }
  };
}

module.exports = {
  checkAbuseIPDB
};
