const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticateToken, optionalAuth } = require('../middleware/auth');
const rateLimiter = require('../middleware/rateLimiter');
const {
  validateRegistration,
  validateLogin,
  validateOTP,
  validatePasswordResetRequest,
  validatePasswordReset,
  validateProfileUpdate,
  validateChangePassword,
  validate2FAToken
} = require('../middleware/validation');

/**
 * Authentication Routes
 * All routes related to user authentication, registration, and account management
 */

// Public authentication routes (with rate limiting)

/**
 * POST /api/auth/signup
 * Register a new user account
 */
router.post('/signup', 
  rateLimiter.registration,
  validateRegistration,
  authController.signup
);

/**
 * POST /api/auth/login
 * Login with email and password
 */
router.post('/login',
  rateLimiter.auth,
  validateLogin,
  authController.login
);

/**
 * POST /api/auth/verify-otp
 * Verify OTP for 2FA login
 */
router.post('/verify-otp',
  rateLimiter.otp,
  validateOTP,
  authController.verifyOTP
);

/**
 * POST /api/auth/refresh
 * Refresh access token using refresh token
 */
router.post('/refresh',
  rateLimiter.auth,
  authController.refreshToken
);

/**
 * POST /api/auth/forgot-password
 * Send password reset email
 */
router.post('/forgot-password',
  rateLimiter.passwordReset,
  validatePasswordResetRequest,
  authController.forgotPassword
);

/**
 * POST /api/auth/reset-password
 * Reset password with token from email
 */
router.post('/reset-password',
  rateLimiter.passwordReset,
  validatePasswordReset,
  authController.resetPassword
);

// Protected authentication routes (require authentication)

/**
 * GET /api/auth/me
 * Get current user profile
 */
router.get('/me',
  authenticateToken,
  authController.getProfile
);

/**
 * PUT /api/auth/profile
 * Update user profile information
 */
router.put('/profile',
  authenticateToken,
  rateLimiter.general,
  validateProfileUpdate,
  authController.updateProfile
);

/**
 * POST /api/auth/change-password
 * Change user password (requires current password)
 */
router.post('/change-password',
  authenticateToken,
  rateLimiter.authStrict,
  validateChangePassword,
  authController.changePassword
);

/**
 * POST /api/auth/logout
 * Logout user (client-side token invalidation)
 */
router.post('/logout',
  authenticateToken,
  authController.logout
);

// Two-Factor Authentication routes

/**
 * POST /api/auth/setup-2fa
 * Setup 2FA and generate backup codes
 */
router.post('/setup-2fa',
  authenticateToken,
  rateLimiter.authStrict,
  authController.setup2FA
);

/**
 * POST /api/auth/enable-2fa
 * Enable 2FA after verification
 */
router.post('/enable-2fa',
  authenticateToken,
  rateLimiter.authStrict,
  validate2FAToken,
  authController.enable2FA
);

/**
 * POST /api/auth/disable-2fa
 * Disable 2FA (requires password or backup code)
 */
router.post('/disable-2fa',
  authenticateToken,
  rateLimiter.authStrict,
  authController.disable2FA
);

/**
 * GET /api/auth/2fa-status
 * Get 2FA status for current user
 */
router.get('/2fa-status',
  authenticateToken,
  authController.get2FAStatus || ((req, res) => {
    res.json({
      success: true,
      data: {
        enabled: req.user.twoFactorEnabled || false
      }
    });
  })
);

/**
 * POST /api/auth/send-otp
 * Send OTP to user's email (for various purposes)
 */
router.post('/send-otp',
  rateLimiter.otp,
  authController.sendOTP || ((req, res) => {
    res.status(501).json({
      success: false,
      message: 'Send OTP functionality not implemented'
    });
  })
);

module.exports = router;