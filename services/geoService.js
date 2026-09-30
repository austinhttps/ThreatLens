const axios = require('axios');
const dns = require('dns').promises;

/**
 * IP Geolocation & ASN Intelligence Service
 * Uses ip-api.com (Free endpoint: 45 req/min)
 */

async function getGeolocation(target, type) {
  // Geolocation is not applicable for raw file hashes
  if (type === 'hash') {
    return {
      status: 'not_applicable',
      provider: 'IP-API Geolocation',
      isMock: false,
      message: 'Geolocation and ASN intelligence are not applicable for file hashes.',
      data: null
    };
  }

  let queryTarget = target;
  let resolvedIp = null;

  if (type === 'domain') {
    try {
      const dnsResult = await dns.lookup(target);
      resolvedIp = dnsResult.address;
    } catch (err) {
      // If DNS resolution fails locally, let ip-api try resolving or use fallback
      resolvedIp = null;
    }
  } else {
    resolvedIp = target;
  }

  try {
    const lookupTarget = resolvedIp || target;
    const response = await axios.get(`http://ip-api.com/json/${encodeURIComponent(lookupTarget)}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse`, {
      timeout: 5000
    });

    if (response.data && response.data.status === 'success') {
      const d = response.data;
      return {
        status: 'success',
        provider: 'IP-API (Live)',
        isMock: false,
        data: {
          query: d.query,
          resolvedIp: resolvedIp || d.query,
          country: d.country || 'Unknown',
          countryCode: d.countryCode || 'UN',
          regionName: d.regionName || 'Unknown',
          city: d.city || 'Unknown',
          zip: d.zip || 'N/A',
          lat: d.lat || 0,
          lon: d.lon || 0,
          timezone: d.timezone || 'UTC',
          isp: d.isp || 'Unknown ISP',
          org: d.org || 'Unknown Org',
          asn: d.as || 'N/A',
          reverseDns: d.reverse || 'N/A'
        }
      };
    } else {
      throw new Error(response.data?.message || 'Failed to query ip-api.com');
    }
  } catch (err) {
    // Graceful fallback / mock for demo resilience
    return generateMockGeo(target, type, resolvedIp, err.message);
  }
}

function generateMockGeo(target, type, resolvedIp, reason) {
  // Deterministic mock based on target chars
  const charSum = target.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
  const sampleLocations = [
    { country: 'United States', countryCode: 'US', regionName: 'Virginia', city: 'Ashburn', zip: '20147', lat: 39.0438, lon: -77.4874, timezone: 'America/New_York', isp: 'DigitalOcean, LLC', org: 'DigitalOcean Cloud Infrastructure', asn: 'AS14061 DigitalOcean, LLC' },
    { country: 'Netherlands', countryCode: 'NL', regionName: 'North Holland', city: 'Amsterdam', zip: '1012', lat: 52.3676, lon: 4.9041, timezone: 'Europe/Amsterdam', isp: 'Leaseweb Netherlands B.V.', org: 'Hosting & Server Solutions', asn: 'AS60781 LEASEWEB' },
    { country: 'Germany', countryCode: 'DE', regionName: 'Hesse', city: 'Frankfurt am Main', zip: '60311', lat: 50.1109, lon: 8.6821, timezone: 'Europe/Berlin', isp: 'Hetzner Online GmbH', org: 'Hetzner Datacenter Services', asn: 'AS24940 Hetzner Online GmbH' },
    { country: 'Singapore', countryCode: 'SG', regionName: 'Central Singapore', city: 'Singapore', zip: '018989', lat: 1.2897, lon: 103.8501, timezone: 'Asia/Singapore', isp: 'Amazon.com, Inc.', org: 'AWS Cloud EC2 AP-Southeast', asn: 'AS16509 AMAZON-02' },
    { country: 'Russia', countryCode: 'RU', regionName: 'Moscow', city: 'Moscow', zip: '101000', lat: 55.7558, lon: 37.6173, timezone: 'Europe/Moscow', isp: 'Selectel Network', org: 'Hosting and Cloud Services RU', asn: 'AS49505 SELECTEL' }
  ];

  const loc = sampleLocations[charSum % sampleLocations.length];
  const ip = resolvedIp || (type === 'ip' ? target : `194.165.16.${(charSum % 250) + 1}`);

  return {
    status: 'success',
    provider: 'IP-API [Demo/Mock Mode]',
    isMock: true,
    mockReason: reason || 'Demo/Fallback Mode',
    data: {
      query: ip,
      resolvedIp: ip,
      country: loc.country,
      countryCode: loc.countryCode,
      regionName: loc.regionName,
      city: loc.city,
      zip: loc.zip,
      lat: loc.lat,
      lon: loc.lon,
      timezone: loc.timezone,
      isp: loc.isp,
      org: loc.org,
      asn: loc.asn,
      reverseDns: `host-${ip.replace(/\./g, '-')}.infra.net`
    }
  };
}

module.exports = {
  getGeolocation
};
