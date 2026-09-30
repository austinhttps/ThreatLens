require('dotenv').config();
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const NodeCache = require('node-cache');

const { validateTarget } = require('./services/validator');
const { aggregateThreatIntel } = require('./services/aggregator');

const app = express();
const PORT = process.env.PORT || 3000;
const CACHE_TTL = parseInt(process.env.CACHE_TTL_SECONDS || '900', 10); // 15 minutes default

// Initialize In-Memory Cache with 15-minute TTL & 2-minute check period
const intelCache = new NodeCache({
  stdTTL: CACHE_TTL,
  checkperiod: 120,
  useClones: false
});

// Trust proxy if behind reverse proxy (e.g. Nginx/Cloudflare)
app.set('trust proxy', 1);

// Security Headers with Helmet (Configured for OpenStreetMap Tile Usage Policy)
app.use(helmet({
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }, // OSM Policy requires HTTP Referer from web pages
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.tailwindcss.com",
        "https://unpkg.com",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com"
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com",
        "https://cdn.jsdelivr.net",
        "https://unpkg.com",
        "https://cdnjs.cloudflare.com"
      ],
      fontSrc: [
        "'self'",
        "https://fonts.gstatic.com",
        "https://cdnjs.cloudflare.com"
      ],
      imgSrc: [
        "'self'",
        "data:",
        "https://tile.openstreetmap.org",
        "https://*.tile.openstreetmap.org",
        "https:",
        "http:"
      ],
      connectSrc: ["'self'", "https://tile.openstreetmap.org"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

// CORS Configuration
app.use(cors());

// Parse JSON Bodies
app.use(express.json({ limit: '100kb' }));

// Rate Limiting: 30 requests per minute per IP
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests from this IP. Rate limit is 30 lookups per minute. Please wait a moment before trying again.'
  }
});

// Serve Static Frontend Assets
app.use(express.static(path.join(__dirname, 'public')));

// ----------------------------------------------------
// API ROUTES
// ----------------------------------------------------

/**
 * POST /api/lookup
 * Primary OSINT Intelligence Aggregation Endpoint
 */
app.post('/api/lookup', apiLimiter, async (req, res) => {
  try {
    const { target } = req.body;

    if (!target) {
      return res.status(400).json({
        success: false,
        error: 'Target parameter is required in request body (e.g. { "target": "185.220.101.5" })'
      });
    }

    // 1. Validate and classify target
    const targetInfo = validateTarget(target);
    if (!targetInfo.isValid) {
      return res.status(422).json({
        success: false,
        error: targetInfo.error,
        originalInput: target
      });
    }

    // 2. Check in-memory cache
    const cacheKey = `intel:${targetInfo.type}:${targetInfo.sanitized}`;
    const cachedData = intelCache.get(cacheKey);

    if (cachedData) {
      const ttlRemaining = intelCache.getTtl(cacheKey);
      const expiresAt = ttlRemaining ? new Date(ttlRemaining).toISOString() : null;

      return res.json({
        success: true,
        cached: true,
        cacheExpiresAt: expiresAt,
        data: cachedData
      });
    }

    // 3. Perform asynchronous multi-provider lookup
    const intelReport = await aggregateThreatIntel(targetInfo);

    // 4. Store result in Cache with 15-minute TTL
    intelCache.set(cacheKey, intelReport);

    const ttlRemaining = intelCache.getTtl(cacheKey);
    const expiresAt = ttlRemaining ? new Date(ttlRemaining).toISOString() : null;

    return res.json({
      success: true,
      cached: false,
      cacheExpiresAt: expiresAt,
      data: intelReport
    });

  } catch (error) {
    console.error('[ThreatLens API Error]', error);
    return res.status(500).json({
      success: false,
      error: 'An unexpected internal error occurred while aggregating threat intelligence.',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * GET /api/health
 * Service status, cache metrics, and provider API configurations
 */
app.get('/api/health', (req, res) => {
  const cacheStats = intelCache.getStats();
  const keysCount = intelCache.keys().length;

  res.json({
    status: 'online',
    appName: 'ThreatLens OSINT Aggregator',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    cache: {
      activeKeys: keysCount,
      hits: cacheStats.hits,
      misses: cacheStats.misses,
      ttlSeconds: CACHE_TTL
    },
    providers: {
      ipApi: { status: 'active', mode: 'live_free_tier' },
      abuseIPDB: {
        status: process.env.ABUSEIPDB_API_KEY ? 'configured' : 'demo_mock_mode',
        hasKey: Boolean(process.env.ABUSEIPDB_API_KEY)
      },
      virusTotal: {
        status: process.env.VIRUSTOTAL_API_KEY ? 'configured' : 'demo_mock_mode',
        hasKey: Boolean(process.env.VIRUSTOTAL_API_KEY)
      }
    }
  });
});

/**
 * GET /api/sample-targets
 * Provides pre-set sample IOCs for testing and demonstration
 */
app.get('/api/sample-targets', (req, res) => {
  res.json({
    success: true,
    samples: [
      {
        label: 'Tor Exit / Malicious IP',
        type: 'ip',
        target: '185.220.101.5',
        description: 'Known high-volume scanner and Tor Exit Node.'
      },
      {
        label: 'Google Public DNS',
        type: 'ip',
        target: '8.8.8.8',
        description: 'Clean, verified Google Anycast DNS resolver.'
      },
      {
        label: 'C2 CobaltStrike Domain',
        type: 'domain',
        target: 'c2-beacon-command.biz',
        description: 'Simulated adversary Command & Control infrastructure.'
      },
      {
        label: 'GitHub Official Domain',
        type: 'domain',
        target: 'github.com',
        description: 'Legitimate enterprise development platform.'
      },
      {
        label: 'WannaCry Ransomware Hash',
        type: 'hash',
        target: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
        description: 'SHA-256 binary hash of WannaCry Ransomware payload.'
      },
      {
        label: 'EICAR Test File Hash',
        type: 'hash',
        target: '44d88612fea8a8f36de82e1278abb02f',
        description: 'MD5 hash of the standard EICAR anti-virus test file.'
      }
    ]
  });
});

// Fallback index.html route for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🛡️  ThreatLens OSINT Aggregator running on http://localhost:${PORT}`);
  console.log(`⚡ In-memory cache TTL set to ${CACHE_TTL} seconds (15 mins)`);
  console.log(`🔑 AbuseIPDB Key: ${process.env.ABUSEIPDB_API_KEY ? 'CONFIGURED (Live)' : 'NOT SET (Demo Mode)'}`);
  console.log(`🔑 VirusTotal Key: ${process.env.VIRUSTOTAL_API_KEY ? 'CONFIGURED (Live)' : 'NOT SET (Demo Mode)'}`);
  console.log(`====================================================`);
});
