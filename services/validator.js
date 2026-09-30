/**
 * Target Input Validator & IOC Refanger
 * Identifies and sanitizes IPv4 addresses, domains, and cryptographic hashes (MD5, SHA1, SHA256)
 */

function refang(input) {
  if (!input || typeof input !== 'string') return '';
  let str = input.trim();
  
  // Defang patterns: hxxp -> http, [.] -> ., [:] -> :, etc.
  str = str.replace(/^hxxps?:\/\//i, '');
  str = str.replace(/^https?:\/\//i, '');
  str = str.replace(/\[\.\]/g, '.');
  str = str.replace(/\(\.\)/g, '.');
  str = str.replace(/\[:\]/g, ':');
  str = str.replace(/\/:/g, '/');
  // Strip trailing path/query if user pasted a full URL
  if (str.includes('/')) {
    str = str.split('/')[0];
  }
  return str.trim();
}

function validateTarget(rawInput) {
  if (!rawInput || typeof rawInput !== 'string') {
    return {
      isValid: false,
      error: 'Target input is required and must be a non-empty string.'
    };
  }

  const sanitized = refang(rawInput);

  if (!sanitized) {
    return {
      isValid: false,
      error: 'Target is empty after removing URL wrappers/defanging.'
    };
  }

  // 1. IPv4 Regex (Strict octets 0-255)
  const ipv4Regex = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  if (ipv4Regex.test(sanitized)) {
    return {
      isValid: true,
      type: 'ip',
      subType: 'ipv4',
      sanitized: sanitized,
      original: rawInput
    };
  }

  // 2. Hash Regexes (MD5, SHA-1, SHA-256)
  const md5Regex = /^[a-fA-F0-9]{32}$/;
  const sha1Regex = /^[a-fA-F0-9]{40}$/;
  const sha256Regex = /^[a-fA-F0-9]{64}$/;

  if (md5Regex.test(sanitized)) {
    return {
      isValid: true,
      type: 'hash',
      subType: 'md5',
      sanitized: sanitized.toLowerCase(),
      original: rawInput
    };
  }

  if (sha1Regex.test(sanitized)) {
    return {
      isValid: true,
      type: 'hash',
      subType: 'sha1',
      sanitized: sanitized.toLowerCase(),
      original: rawInput
    };
  }

  if (sha256Regex.test(sanitized)) {
    return {
      isValid: true,
      type: 'hash',
      subType: 'sha256',
      sanitized: sanitized.toLowerCase(),
      original: rawInput
    };
  }

  // 3. Domain Name Regex (FQDN with valid TLD, excluding IPv4 format)
  // Max label 63 chars, valid letters, numbers, hyphens
  const domainRegex = /^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.[a-zA-Z]{2,63}$/;
  if (domainRegex.test(sanitized)) {
    return {
      isValid: true,
      type: 'domain',
      subType: 'domain',
      sanitized: sanitized.toLowerCase(),
      original: rawInput
    };
  }

  return {
    isValid: false,
    error: `Invalid target format: "${sanitized}". ThreatLens accepts valid IPv4 addresses (e.g. 185.220.101.5), Domain names (e.g. bad-actor.cc), or File Hashes (MD5, SHA1, SHA256).`,
    original: rawInput
  };
}

module.exports = {
  validateTarget,
  refang
};
