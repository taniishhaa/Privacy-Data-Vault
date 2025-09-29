// src/middleware/rateLimiter.js
const rateLimit = require('express-rate-limit');

// Store for tracking requests (in production, use Redis)
const store = new Map();

// Custom store implementation for in-memory rate limiting
class MemoryStore {
  constructor() {
    this.hits = new Map();
    this.resetTime = new Map();
  }

  incr(key, cb) {
    const now = Date.now();
    const resetTime = this.resetTime.get(key);
    
    if (!resetTime || now > resetTime) {
      this.hits.set(key, 1);
      this.resetTime.set(key, now + (15 * 60 * 1000)); // 15 minutes
      return cb(null, 1, now + (15 * 60 * 1000));
    }
    
    const hits = (this.hits.get(key) || 0) + 1;
    this.hits.set(key, hits);
    cb(null, hits, resetTime);
  }

  decrement(key) {
    const hits = this.hits.get(key);
    if (hits && hits > 0) {
      this.hits.set(key, hits - 1);
    }
  }

  resetKey(key) {
    this.hits.delete(key);
    this.resetTime.delete(key);
  }
}

// Create custom key generator
const createKeyGenerator = (prefix = '') => {
  return (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = forwarded ? forwarded.split(/, /)[0] : req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'] || 'unknown';
    const userInfo = req.user ? req.user.id : 'anonymous';
    return `${prefix}:${ip}:${userInfo}:${userAgent.substring(0, 50)}`;
  };
};

// Custom message handler
const createMessageHandler = (type) => {
  return (req, res) => {
    const retryAfter = Math.round(req.rateLimit.resetTime / 1000) || 1;
    
    res.status(429).json({
      success: false,
      error: {
        type: 'RATE_LIMIT_EXCEEDED',
        message: `Too many ${type} requests. Please try again later.`,
        retryAfter: retryAfter,
        limit: req.rateLimit.limit,
        current: req.rateLimit.current,
        remaining: req.rateLimit.remaining
      }
    });
  };
};

// General rate limiter (100 requests per 15 minutes)
const general = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  keyGenerator: createKeyGenerator('general'),
  handler: createMessageHandler('general'),
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  skip: (req) => {
    // Skip rate limiting for health checks
    return req.path === '/health';
  }
});

// Authentication rate limiter (5 login attempts per 15 minutes)
const auth = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 authentication requests per windowMs
  keyGenerator: createKeyGenerator('auth'),
  handler: createMessageHandler('authentication'),
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true // Don't count successful requests
});

// Strict authentication rate limiter (3 attempts per hour for sensitive operations)
const authStrict = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 requests per hour
  keyGenerator: createKeyGenerator('auth-strict'),
  handler: createMessageHandler('sensitive authentication'),
  standardHeaders: true,
  legacyHeaders: false
});

// Registration rate limiter (3 registrations per hour)
const registration = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 registration attempts per hour
  keyGenerator: createKeyGenerator('registration'),
  handler: createMessageHandler('registration'),
  standardHeaders: true,
  legacyHeaders: false
});

// OTP rate limiter (10 OTP requests per hour)
const otp = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // limit each IP to 10 OTP requests per hour
  keyGenerator: createKeyGenerator('otp'),
  handler: createMessageHandler('OTP'),
  standardHeaders: true,
  legacyHeaders: false
});

// Password reset rate limiter (3 attempts per hour)
const passwordReset = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // limit each IP to 3 password reset requests per hour
  keyGenerator: createKeyGenerator('password-reset'),
  handler: createMessageHandler('password reset'),
  standardHeaders: true,
  legacyHeaders: false
});

// Vault operations rate limiter (50 requests per 15 minutes)
const vaultOperations = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // limit each IP to 50 vault operations per windowMs
  keyGenerator: createKeyGenerator('vault'),
  handler: createMessageHandler('vault operations'),
  standardHeaders: true,
  legacyHeaders: false
});

// Disclosure creation rate limiter (10 disclosures per hour)
const disclosure = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // limit each IP to 10 disclosure creations per hour
  keyGenerator: createKeyGenerator('disclosure'),
  handler: createMessageHandler('disclosure'),
  standardHeaders: true,
  legacyHeaders: false
});

// Verification rate limiter (100 verifications per 15 minutes)
const verification = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 verifications per windowMs
  keyGenerator: createKeyGenerator('verification'),
  handler: createMessageHandler('verification'),
  standardHeaders: true,
  legacyHeaders: false
});

// Data export rate limiter (5 exports per day)
const dataExport = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 24 hours
  max: 5, // limit each IP to 5 exports per day
  keyGenerator: createKeyGenerator('export'),
  handler: createMessageHandler('data export'),
  standardHeaders: true,
  legacyHeaders: false
});

// Admin operations rate limiter (100 requests per 15 minutes)
const admin = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each admin to 100 requests per windowMs
  keyGenerator: createKeyGenerator('admin'),
  handler: createMessageHandler('admin operations'),
  standardHeaders: true,
  legacyHeaders: false
});

// API rate limiter for external integrations (1000 requests per hour)
const api = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 1000, // limit each API key to 1000 requests per hour
  keyGenerator: (req) => {
    const apiKey = req.headers['x-api-key'] || req.query.apiKey;
    const ip = req.ip;
    return `api:${apiKey || ip}`;
  },
  handler: createMessageHandler('API'),
  standardHeaders: true,
  legacyHeaders: false
});

// Progressive rate limiter that increases limits for verified users
const createProgressiveRateLimit = (baseLimit, multiplier = 2) => {
  return (req, res, next) => {
    const isVerified = req.user?.isVerified || false;
    const isPremium = req.user?.isPremium || false;
    
    let limit = baseLimit;
    if (isVerified) limit *= multiplier;
    if (isPremium) limit *= multiplier;
    
    const dynamicLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: limit,
      keyGenerator: createKeyGenerator('progressive'),
      handler: createMessageHandler('progressive'),
      standardHeaders: true,
      legacyHeaders: false
    });
    
    return dynamicLimiter(req, res, next);
  };
};

// Burst protection - allows short bursts but enforces overall limits
const burstProtection = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute window
  max: 20, // allow 20 requests per minute
  keyGenerator: createKeyGenerator('burst'),
  handler: createMessageHandler('burst protection'),
  standardHeaders: true,
  legacyHeaders: false
});

// Custom middleware to combine multiple rate limiters
const createMultiLimiter = (...limiters) => {
  return (req, res, next) => {
    let index = 0;
    
    const runNext = () => {
      if (index >= limiters.length) {
        return next();
      }
      
      const limiter = limiters[index++];
      limiter(req, res, (err) => {
        if (err) return next(err);
        runNext();
      });
    };
    
    runNext();
  };
};

// Whitelist middleware (skip rate limiting for trusted IPs)
const createWhitelistMiddleware = (whitelist = []) => {
  return (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    if (whitelist.includes(clientIP)) {
      return next();
    }
    
    // Apply general rate limiting
    return general(req, res, next);
  };
};

// Clean up expired entries periodically
setInterval(() => {
  // In a real application, you'd clean up your storage here
  console.log('🧹 Cleaning up rate limiter cache...');
}, 60 * 60 * 1000); // Clean up every hour

module.exports = {
  general,
  auth,
  authStrict,
  registration,
  otp,
  passwordReset,
  vaultOperations,
  disclosure,
  verification,
  dataExport,
  admin,
  api,
  burstProtection,
  createProgressiveRateLimit,
  createMultiLimiter,
  createWhitelistMiddleware,
  
  // Custom rate limiters for specific scenarios
  strictAuth: authStrict,
  sensitiveOps: authStrict,
  publicAPI: api,
  
  // Helper functions
  createKeyGenerator,
  createMessageHandler
};
