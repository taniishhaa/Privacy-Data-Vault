const jwtConfig = require('../config/jwt');
const User = require('../model/User');

/**
 * Authentication Middleware
 * Handles JWT token verification and user authorization
 */

/**
 * Extract JWT token from request headers
 * @param {Object} req - Express request object
 * @returns {string|null} JWT token or null
 */
function extractToken(req) {
  // Check Authorization header
  if (req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      return parts[1];
    }
  }
  
  // Check query parameter (for testing purposes)
  if (req.query.token) {
    return req.query.token;
  }
  
  // Check body (for some specific endpoints)
  if (req.body.token) {
    return req.body.token;
  }
  
  return null;
}

/**
 * Verify JWT token and authenticate user
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const authenticateToken = async (req, res, next) => {
  try {
    const token = extractToken(req);
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token is required',
        error: {
          type: 'MISSING_TOKEN',
          message: 'No authentication token provided'
        }
      });
    }

    // Verify the token
    const decoded = jwtConfig.verifyAccessToken(token);
    
    // Find user by ID from token payload
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found',
        error: {
          type: 'USER_NOT_FOUND',
          message: 'User associated with token no longer exists'
        }
      });
    }

    // Check if user account is active
    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Account is deactivated',
        error: {
          type: 'ACCOUNT_INACTIVE',
          message: 'User account has been deactivated'
        }
      });
    }

    // Check if account is locked
    if (user.isAccountLocked()) {
      const lockoutTime = Math.ceil((user.security.lockoutUntil - Date.now()) / (1000 * 60));
      return res.status(423).json({
        success: false,
        message: 'Account is temporarily locked',
        error: {
          type: 'ACCOUNT_LOCKED',
          message: `Account is locked due to multiple failed login attempts. Try again in ${lockoutTime} minutes.`
        }
      });
    }

    // Add user info to request object
    req.user = {
      id: user._id.toString(),
      email: user.email,
      username: user.username,
      role: user.role,
      isVerified: user.isVerified,
      twoFactorEnabled: user.twoFactorAuth.enabled
    };

    // Update last active time
    user.lastActiveAt = new Date();
    await user.save();

    next();
  } catch (error) {
    console.error('Authentication error:', error.message);
    
    if (error.message.includes('expired')) {
      return res.status(401).json({
        success: false,
        message: 'Token has expired',
        error: {
          type: 'TOKEN_EXPIRED',
          message: 'Authentication token has expired. Please log in again.'
        }
      });
    } else if (error.message.includes('Invalid')) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token',
        error: {
          type: 'INVALID_TOKEN',
          message: 'Authentication token is invalid'
        }
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Authentication failed',
      error: {
        type: 'AUTH_ERROR',
        message: 'Internal authentication error'
      }
    });
  }
};

/**
 * Require admin role middleware
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required',
      error: {
        type: 'AUTHENTICATION_REQUIRED',
        message: 'Please authenticate first'
      }
    });
  }

  if (req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Admin access required',
      error: {
        type: 'INSUFFICIENT_PERMISSIONS',
        message: 'This operation requires administrator privileges'
      }
    });
  }

  next();
};

/**
 * Require 2FA for sensitive operations
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const require2FA = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
        error: {
          type: 'AUTHENTICATION_REQUIRED',
          message: 'Please authenticate first'
        }
      });
    }

    // Get full user details to check 2FA status
    const user = await User.findById(req.user.id).select('+twoFactorAuth');
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found',
        error: {
          type: 'USER_NOT_FOUND',
          message: 'User not found'
        }
      });
    }

    // Skip 2FA requirement if not enabled (optional enforcement)
    // In production, you might want to require 2FA for all sensitive operations
    if (!user.twoFactorAuth.enabled) {
      console.warn(`⚠️ User ${user.username} performing sensitive operation without 2FA enabled`);
    }

    next();
  } catch (error) {
    console.error('2FA check error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Failed to verify 2FA status',
      error: {
        type: 'INTERNAL_ERROR',
        message: 'Internal server error during 2FA verification'
      }
    });
  }
};

/**
 * Optional authentication middleware (doesn't fail if no token)
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const optionalAuth = async (req, res, next) => {
  try {
    const token = extractToken(req);
    
    if (!token) {
      // No token provided, continue without authentication
      req.user = null;
      return next();
    }

    // Try to verify token but don't fail if invalid
    try {
      const decoded = jwtConfig.verifyAccessToken(token);
      const user = await User.findById(decoded.id);
      
      if (user && user.isActive && !user.isAccountLocked()) {
        req.user = {
          id: user._id.toString(),
          email: user.email,
          username: user.username,
          role: user.role,
          isVerified: user.isVerified,
          twoFactorEnabled: user.twoFactorAuth.enabled
        };
      } else {
        req.user = null;
      }
    } catch (tokenError) {
      // Invalid token, but continue without authentication
      req.user = null;
    }

    next();
  } catch (error) {
    console.error('Optional authentication error:', error.message);
    req.user = null;
    next();
  }
};

/**
 * Create rate-limited sensitive operation middleware
 * @param {number} maxAttempts - Maximum attempts allowed
 * @param {number} windowMs - Time window in milliseconds
 * @returns {Function} Express middleware function
 */
const sensitiveOpLimiter = (maxAttempts = 5, windowMs = 15 * 60 * 1000) => {
  const attempts = new Map();
  
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
        error: {
          type: 'AUTHENTICATION_REQUIRED',
          message: 'Authentication is required for this operation'
        }
      });
    }

    const userId = req.user.id;
    const now = Date.now();
    const userAttempts = attempts.get(userId) || { count: 0, firstAttempt: now };

    // Reset attempts if window has passed
    if (now - userAttempts.firstAttempt > windowMs) {
      userAttempts.count = 0;
      userAttempts.firstAttempt = now;
    }

    // Check if user has exceeded attempts
    if (userAttempts.count >= maxAttempts) {
      const resetTime = new Date(userAttempts.firstAttempt + windowMs);
      return res.status(429).json({
        success: false,
        message: 'Too many attempts',
        error: {
          type: 'RATE_LIMIT_EXCEEDED',
          message: `Too many sensitive operations attempted. Try again after ${resetTime.toLocaleTimeString()}`
        },
        retryAfter: Math.ceil((resetTime - now) / 1000)
      });
    }

    // Increment attempts
    userAttempts.count++;
    attempts.set(userId, userAttempts);

    // Clean up old entries periodically
    if (Math.random() < 0.01) { // 1% chance
      for (const [key, value] of attempts.entries()) {
        if (now - value.firstAttempt > windowMs) {
          attempts.delete(key);
        }
      }
    }

    next();
  };
};

/**
 * Middleware to check if user owns a resource
 * @param {string} resourceIdField - Field name containing resource ID
 * @param {string} ownerField - Field name containing owner ID (default: 'userId')
 * @returns {Function} Express middleware function
 */
const checkResourceOwnership = (Model, resourceIdField = 'id', ownerField = 'userId') => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required',
          error: {
            type: 'AUTHENTICATION_REQUIRED',
            message: 'Authentication is required'
          }
        });
      }

      const resourceId = req.params[resourceIdField];
      if (!resourceId) {
        return res.status(400).json({
          success: false,
          message: 'Resource ID is required',
          error: {
            type: 'MISSING_RESOURCE_ID',
            message: `${resourceIdField} parameter is required`
          }
        });
      }

      const resource = await Model.findById(resourceId);
      if (!resource) {
        return res.status(404).json({
          success: false,
          message: 'Resource not found',
          error: {
            type: 'RESOURCE_NOT_FOUND',
            message: 'The requested resource does not exist'
          }
        });
      }

      // Check ownership (admins can access all resources)
      if (req.user.role !== 'admin' && resource[ownerField].toString() !== req.user.id) {
        return res.status(403).json({
          success: false,
          message: 'Access denied',
          error: {
            type: 'ACCESS_DENIED',
            message: 'You do not have permission to access this resource'
          }
        });
      }

      req.resource = resource;
      next();
    } catch (error) {
      console.error('Resource ownership check error:', error.message);
      return res.status(500).json({
        success: false,
        message: 'Failed to verify resource ownership',
        error: {
          type: 'INTERNAL_ERROR',
          message: 'Internal server error'
        }
      });
    }
  };
};

module.exports = {
  authenticateToken,
  requireAdmin,
  require2FA,
  optionalAuth,
  sensitiveOpLimiter,
  checkResourceOwnership,
  extractToken
};
