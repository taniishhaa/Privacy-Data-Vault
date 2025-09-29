const User = require('../model/User');
const Vault = require('../model/Vault');
const encryptionService = require('../services/encryption');
const mailer = require('../services/mailer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { catchAsync, AppError, AuthenticationError, ValidationError, ConflictError } = require('../middleware/errorHandler');

/**
 * Authentication Controller
 * Handles all authentication-related operations including signup, login, 2FA, password management
 */

/**
 * User Registration
 * POST /api/auth/signup
 */
const signup = catchAsync(async (req, res, next) => {
  const { username, email, password, confirmPassword, profile } = req.body;

  // Check if passwords match
  if (password !== confirmPassword) {
    return next(new ValidationError('Passwords do not match'));
  }

  // Check if user already exists
  const existingUser = await User.findOne({
    $or: [{ email }, { username }]
  });

  if (existingUser) {
    if (existingUser.email === email) {
      return next(new ConflictError('An account with this email already exists'));
    }
    if (existingUser.username === username) {
      return next(new ConflictError('This username is already taken'));
    }
  }

  // Hash password
  const passwordHash = await encryptionService.hashPassword(password);

  // Generate email verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  // Create user
  const user = new User({
    username,
    email,
    passwordHash,
    profile: profile || {},
    verification: {
      token: verificationToken,
      expiresAt: verificationExpiry
    },
    isVerified: false,
    isActive: true,
    role: 'user'
  });

  await user.save();

  // Create empty vault for user
  const vault = new Vault({
    userId: user._id,
    encryptedData: {
      personalInfo: {},
      contactInfo: {},
      identificationInfo: {},
      financialInfo: {},
      healthInfo: {},
      educationInfo: {}
    },
    encryptionMetadata: {
      keyDerivationSalt: crypto.randomBytes(32).toString('hex'),
      algorithm: 'aes-256-cbc',
      keyDerivationMethod: 'PBKDF2',
      iterations: 100000,
      encryptedAt: new Date()
    }
  });

  await vault.save();

  // Send verification email
  try {
    const verificationUrl = `${req.protocol}://${req.get('host')}/verify-email?token=${verificationToken}`;
    await mailer.sendVerificationEmail(email, username, verificationUrl);
  } catch (emailError) {
    console.error('Failed to send verification email:', emailError.message);
    // Don't fail registration if email fails
  }

  // Generate JWT tokens (FIXED: userId → id)
  const accessToken = jwt.sign(
    { id: user._id, username, email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
  );

  const refreshToken = jwt.sign(
    { id: user._id, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
  );

  console.log(`🔐 New user registered: ${username} (${email})`);

  res.status(201).json({
    success: true,
    message: 'Account created successfully! Please check your email for verification.',
    data: {
      user: user.toSafeObject(),
      accessToken,
      refreshToken,
      requiresVerification: !user.isVerified
    }
  });
});

/**
 * User Login
 * POST /api/auth/login
 */
const login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // Find user by email
  const user = await User.findOne({ email }).select('+passwordHash +security');

  if (!user) {
    // Track failed login attempt
    console.warn(`🚨 Login attempt with non-existent email: ${email} from ${req.ip}`);
    return next(new AuthenticationError('Invalid email or password'));
  }

  // Check if account is locked
  if (user.security.lockoutUntil && user.security.lockoutUntil > new Date()) {
    const lockoutMinutes = Math.ceil((user.security.lockoutUntil - new Date()) / 60000);
    return next(new AuthenticationError(`Account temporarily locked. Try again in ${lockoutMinutes} minutes.`));
  }

  // Check if account is active
  if (!user.isActive) {
    return next(new AuthenticationError('Account is deactivated. Please contact support.'));
  }

  // Verify password
  const isPasswordValid = await encryptionService.verifyPassword(password, user.passwordHash);

  if (!isPasswordValid) {
    // Increment failed login attempts
    user.security.loginAttempts = (user.security.loginAttempts || 0) + 1;
    user.security.lastFailedLogin = new Date();
    
    // Add IP to failed login IPs
    if (!user.security.failedLoginIPs) {
      user.security.failedLoginIPs = [];
    }
    if (!user.security.failedLoginIPs.includes(req.ip)) {
      user.security.failedLoginIPs.push(req.ip);
    }

    // Lock account after 5 failed attempts
    if (user.security.loginAttempts >= 5) {
      user.security.lockoutUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
      console.warn(`🔒 Account locked due to failed login attempts: ${email}`);
    }

    await user.save();

    return next(new AuthenticationError('Invalid email or password'));
  }

  // Reset security counters on successful login
  user.security.loginAttempts = 0;
  user.security.lockoutUntil = null;
  user.security.lastLoginAt = new Date();
  user.security.lastLoginIP = req.ip;

  // Check if 2FA is enabled
  if (user.twoFactorEnabled) {
    // Generate and send OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    user.otp = {
      code: otp,
      expiresAt: otpExpiry,
      verified: false
    };

    await user.save();

    // Send OTP via email
    try {
      await mailer.sendOTPEmail(email, user.username, otp);
    } catch (emailError) {
      console.error('Failed to send OTP email:', emailError.message);
      return next(new AppError('Failed to send verification code. Please try again.', 500));
    }

    console.log(`📧 2FA OTP sent to: ${email}`);

    return res.status(200).json({
      success: true,
      message: 'Verification code sent to your email',
      data: {
        requiresOTP: true,
        email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3'), // Mask email
        otpExpiresIn: 5 * 60 // seconds
      }
    });
  }

  // Direct login without 2FA (FIXED: userId → id)
  const accessToken = jwt.sign(
    { 
      id: user._id, 
      username: user.username, 
      email: user.email, 
      role: user.role 
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
  );

  const refreshToken = jwt.sign(
    { id: user._id, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
  );

  console.log(`✅ User logged in: ${user.username} (${email})`);

  res.status(200).json({
    success: true,
    message: 'Login successful',
    data: {
      user: user.toSafeObject(),
      accessToken,
      refreshToken
    }
  });
});

/**
 * Verify OTP for 2FA
 * POST /api/auth/verify-otp
 */
const verifyOTP = catchAsync(async (req, res, next) => {
  const { email, otp } = req.body;

  // Find user
  const user = await User.findOne({ email }).select('+otp');

  if (!user) {
    return next(new AuthenticationError('Invalid verification attempt'));
  }

  // Check if OTP exists and is not expired
  if (!user.otp || !user.otp.code || user.otp.expiresAt < new Date()) {
    return next(new AuthenticationError('Verification code has expired. Please login again.'));
  }

  // Verify OTP
  if (user.otp.code !== otp) {
    return next(new AuthenticationError('Invalid verification code'));
  }

  // Mark OTP as verified and clear it
  user.otp = {
    code: null,
    expiresAt: null,
    verified: true
  };

  user.security.lastLoginAt = new Date();
  user.security.lastLoginIP = req.ip;

  await user.save();

  // Generate JWT tokens (FIXED: userId → id)
  const accessToken = jwt.sign(
    { 
      id: user._id, 
      username: user.username, 
      email: user.email, 
      role: user.role 
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
  );

  const refreshToken = jwt.sign(
    { id: user._id, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
  );

  console.log(`✅ 2FA verification successful: ${user.username} (${email})`);

  res.status(200).json({
    success: true,
    message: 'Verification successful',
    data: {
      user: user.toSafeObject(),
      accessToken,
      refreshToken
    }
  });
});

/**
 * Refresh Access Token
 * POST /api/auth/refresh
 */
const refreshToken = catchAsync(async (req, res, next) => {
  const { refreshToken: token } = req.body;

  if (!token) {
    return next(new AuthenticationError('Refresh token is required'));
  }

  try {
    // Verify refresh token
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);

    if (decoded.type !== 'refresh') {
      return next(new AuthenticationError('Invalid token type'));
    }

    // Find user (FIXED: userId → id)
    const user = await User.findById(decoded.id);

    if (!user || !user.isActive) {
      return next(new AuthenticationError('User not found or inactive'));
    }

    // Generate new access token (FIXED: userId → id)
    const accessToken = jwt.sign(
      { 
        id: user._id, 
        username: user.username, 
        email: user.email, 
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '15m' }
    );

    // Optionally generate new refresh token (token rotation)
    const newRefreshToken = jwt.sign(
      { id: user._id, type: 'refresh' },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
    );

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken,
        refreshToken: newRefreshToken
      }
    });

  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return next(new AuthenticationError('Invalid or expired refresh token'));
    }
    throw error;
  }
});

/**
 * Get User Profile
 * GET /api/auth/me
 */
const getProfile = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id).populate({
    path: 'vaultId',
    select: 'createdAt updatedAt'
  });

  if (!user) {
    return next(new AuthenticationError('User not found'));
  }

  res.status(200).json({
    success: true,
    message: 'Profile retrieved successfully',
    data: {
      user: user.toSafeObject()
    }
  });
});

/**
 * Update User Profile
 * PUT /api/auth/profile
 */
const updateProfile = catchAsync(async (req, res, next) => {
  const { profile } = req.body;
  const allowedFields = ['firstName', 'lastName', 'phoneNumber', 'dateOfBirth', 'bio'];

  // Filter allowed fields
  const filteredProfile = {};
  if (profile) {
    Object.keys(profile).forEach(key => {
      if (allowedFields.includes(key) && profile[key] !== undefined) {
        filteredProfile[key] = profile[key];
      }
    });
  }

  const user = await User.findByIdAndUpdate(
    req.user.id,
    { $set: { profile: filteredProfile } },
    { new: true, runValidators: true }
  );

  if (!user) {
    return next(new AuthenticationError('User not found'));
  }

  console.log(`👤 Profile updated: ${user.username}`);

  res.status(200).json({
    success: true,
    message: 'Profile updated successfully',
    data: {
      user: user.toSafeObject()
    }
  });
});

/**
 * Change Password
 * POST /api/auth/change-password
 */
const changePassword = catchAsync(async (req, res, next) => {
  const { currentPassword, newPassword, confirmNewPassword } = req.body;

  // Check if new passwords match
  if (newPassword !== confirmNewPassword) {
    return next(new ValidationError('New passwords do not match'));
  }

  // Check password strength
  const passwordValidation = encryptionService.validatePasswordStrength(newPassword);
  if (!passwordValidation.isValid) {
    return next(new ValidationError(`Password requirements: ${passwordValidation.issues.join(', ')}`));
  }

  // Find user with password hash
  const user = await User.findById(req.user.id).select('+passwordHash');

  if (!user) {
    return next(new AuthenticationError('User not found'));
  }

  // Verify current password
  const isCurrentPasswordValid = await encryptionService.verifyPassword(currentPassword, user.passwordHash);

  if (!isCurrentPasswordValid) {
    return next(new AuthenticationError('Current password is incorrect'));
  }

  // Hash new password
  const newPasswordHash = await encryptionService.hashPassword(newPassword);

  // Update password
  user.passwordHash = newPasswordHash;
  user.security.passwordChangedAt = new Date();
  
  // Clear any existing lockouts
  user.security.loginAttempts = 0;
  user.security.lockoutUntil = null;

  await user.save();

  console.log(`🔐 Password changed: ${user.username}`);

  res.status(200).json({
    success: true,
    message: 'Password changed successfully'
  });
});

/**
 * Forgot Password - Send Reset Email
 * POST /api/auth/forgot-password
 */
const forgotPassword = catchAsync(async (req, res, next) => {
  const { email } = req.body;

  // Find user
  const user = await User.findOne({ email });

  if (!user) {
    // Don't reveal if email exists or not
    return res.status(200).json({
      success: true,
      message: 'If an account with this email exists, a password reset link has been sent.'
    });
  }

  // Generate reset token
  const resetToken = crypto.randomBytes(32).toString('hex');
  const resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  user.resetPassword = {
    token: resetToken,
    expiresAt: resetTokenExpiry
  };

  await user.save();

  // Send reset email
  try {
    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password?token=${resetToken}`;
    await mailer.sendPasswordResetEmail(email, user.username, resetUrl);

    console.log(`📧 Password reset email sent to: ${email}`);

    res.status(200).json({
      success: true,
      message: 'Password reset link has been sent to your email address.'
    });

  } catch (emailError) {
    // Clear reset token if email fails
    user.resetPassword = {
      token: null,
      expiresAt: null
    };
    await user.save();

    console.error('Failed to send password reset email:', emailError.message);
    return next(new AppError('Failed to send reset email. Please try again later.', 500));
  }
});

/**
 * Reset Password
 * POST /api/auth/reset-password
 */
const resetPassword = catchAsync(async (req, res, next) => {
  const { token, newPassword, confirmPassword } = req.body;

  // Check if passwords match
  if (newPassword !== confirmPassword) {
    return next(new ValidationError('Passwords do not match'));
  }

  // Check password strength
  const passwordValidation = encryptionService.validatePasswordStrength(newPassword);
  if (!passwordValidation.isValid) {
    return next(new ValidationError(`Password requirements: ${passwordValidation.issues.join(', ')}`));
  }

  // Find user with valid reset token
  const user = await User.findOne({
    'resetPassword.token': token,
    'resetPassword.expiresAt': { $gt: new Date() }
  }).select('+passwordHash');

  if (!user) {
    return next(new AuthenticationError('Invalid or expired reset token'));
  }

  // Hash new password
  const passwordHash = await encryptionService.hashPassword(newPassword);

  // Update password and clear reset token
  user.passwordHash = passwordHash;
  user.security.passwordChangedAt = new Date();
  user.security.loginAttempts = 0;
  user.security.lockoutUntil = null;
  user.resetPassword = {
    token: null,
    expiresAt: null
  };

  await user.save();

  console.log(`🔐 Password reset completed: ${user.username}`);

  res.status(200).json({
    success: true,
    message: 'Password has been reset successfully. You can now login with your new password.'
  });
});

/**
 * Logout (client-side token invalidation)
 * POST /api/auth/logout
 */
const logout = catchAsync(async (req, res, next) => {
  // In a more sophisticated implementation, you might maintain a blacklist of tokens
  // For now, we rely on client-side token removal

  console.log(`👋 User logged out: ${req.user.username}`);

  res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
});

/**
 * Setup 2FA
 * POST /api/auth/setup-2fa
 */
const setup2FA = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id);

  if (!user) {
    return next(new AuthenticationError('User not found'));
  }

  if (user.twoFactorEnabled) {
    return next(new ValidationError('Two-factor authentication is already enabled'));
  }

  // Generate backup codes
  const backupCodes = [];
  for (let i = 0; i < 10; i++) {
    backupCodes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
  }

  user.twoFactorBackupCodes = backupCodes.map(code => 
    encryptionService.hashPasswordSync(code)
  );

  await user.save();

  console.log(`🔐 2FA setup initiated: ${user.username}`);

  res.status(200).json({
    success: true,
    message: '2FA setup completed. Please save your backup codes safely.',
    data: {
      backupCodes
    }
  });
});

/**
 * Enable 2FA
 * POST /api/auth/enable-2fa
 */
const enable2FA = catchAsync(async (req, res, next) => {
  const { password } = req.body;

  const user = await User.findById(req.user.id).select('+passwordHash');

  if (!user) {
    return next(new AuthenticationError('User not found'));
  }

  // Verify password
  const isPasswordValid = await encryptionService.verifyPassword(password, user.passwordHash);

  if (!isPasswordValid) {
    return next(new AuthenticationError('Invalid password'));
  }

  user.twoFactorEnabled = true;
  user.twoFactorEnabledAt = new Date();

  await user.save();

  console.log(`🔒 2FA enabled: ${user.username}`);

  res.status(200).json({
    success: true,
    message: 'Two-factor authentication has been enabled successfully'
  });
});

/**
 * Disable 2FA
 * POST /api/auth/disable-2fa
 */
const disable2FA = catchAsync(async (req, res, next) => {
  const { password, backupCode } = req.body;

  const user = await User.findById(req.user.id).select('+passwordHash +twoFactorBackupCodes');

  if (!user) {
    return next(new AuthenticationError('User not found'));
  }

  if (!user.twoFactorEnabled) {
    return next(new ValidationError('Two-factor authentication is not enabled'));
  }

  let isAuthorized = false;

  // Verify password if provided
  if (password) {
    isAuthorized = await encryptionService.verifyPassword(password, user.passwordHash);
  }

  // Verify backup code if provided
  if (!isAuthorized && backupCode && user.twoFactorBackupCodes) {
    for (const hashedCode of user.twoFactorBackupCodes) {
      if (encryptionService.verifyPasswordSync(backupCode, hashedCode)) {
        isAuthorized = true;
        break;
      }
    }
  }

  if (!isAuthorized) {
    return next(new AuthenticationError('Invalid password or backup code'));
  }

  // Disable 2FA
  user.twoFactorEnabled = false;
  user.twoFactorBackupCodes = [];
  user.twoFactorEnabledAt = null;

  await user.save();

  console.log(`🔓 2FA disabled: ${user.username}`);

  res.status(200).json({
    success: true,
    message: 'Two-factor authentication has been disabled'
  });
});

module.exports = {
  signup,
  login,
  verifyOTP,
  refreshToken,
  getProfile,
  updateProfile,
  changePassword,
  forgotPassword,
  resetPassword,
  logout,
  setup2FA,
  enable2FA,
  disable2FA
};
