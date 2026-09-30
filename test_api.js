const http = require('http');

function postLookup(target) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ target });
    const req = http.request({
      hostname: 'localhost',
      port: 3000,
      path: '/api/lookup',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(body) });
        } catch (e) {
          resolve({ status: res.statusCode, raw: body });
        }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function runTests() {
  console.log('--- TEST 1: IP Lookup (8.8.8.8) ---');
  const t1 = await postLookup('8.8.8.8');
  console.log(`Status: ${t1.status}, Cached: ${t1.body.cached}, Verdict: ${t1.body.data?.overallRisk?.level}, Score: ${t1.body.data?.overallRisk?.score}`);

  console.log('\n--- TEST 2: Second IP Lookup for Caching Verification ---');
  const t2 = await postLookup('8.8.8.8');
  console.log(`Status: ${t2.status}, Cached: ${t2.body.cached}, CacheExpiresAt: ${t2.body.cacheExpiresAt}`);

  console.log('\n--- TEST 3: Malicious Tor IP (185.220.101.5) ---');
  const t3 = await postLookup('185.220.101.5');
  console.log(`Status: ${t3.status}, Verdict: ${t3.body.data?.overallRisk?.level}, Score: ${t3.body.data?.overallRisk?.score}`);
  console.log('Geo:', t3.body.data?.providers?.geolocation?.data?.country, t3.body.data?.providers?.geolocation?.data?.asn);

  console.log('\n--- TEST 4: Defanged Domain (hxxps://evil-domain[.]com/login) ---');
  const t4 = await postLookup('hxxps://evil-domain[.]com/login');
  console.log(`Status: ${t4.status}, Sanitized: ${t4.body.data?.target}, SubType: ${t4.body.data?.subType}`);

  console.log('\n--- TEST 5: SHA-256 Hash (WannaCry) ---');
  const t5 = await postLookup('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
  console.log(`Status: ${t5.status}, Target: ${t5.body.data?.target}, SubType: ${t5.body.data?.subType}, Verdict: ${t5.body.data?.overallRisk?.level}`);
  console.log('Geo status:', t5.body.data?.providers?.geolocation?.status);

  console.log('\n--- TEST 6: Invalid Input Format ---');
  const t6 = await postLookup('invalid_target_input!@#');
  console.log(`Status: ${t6.status}, Error: ${t6.body?.error}`);
}

runTests().catch(console.error);
