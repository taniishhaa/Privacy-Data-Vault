const mongoose = require('mongoose');

/**
 * User Model Schema
 * Stores user account information with security features
 */
const userSchema = new mongoose.Schema({
  // Basic user information
  username: {
    type: String,
    required: [true, 'Username is required'],
    unique: true,
    trim: true,
    lowercase: true,
    minlength: [3, 'Username must be at least 3 characters long'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
    match: [/^[a-zA-Z0-9_.-]+$/, 'Username can only contain letters, numbers, dots, hyphens, and underscores']
  },
  
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$/, 'Please provide a valid email address']
  },
  
  // Password hash (never store plain text passwords)
  passwordHash: {
    type: String,
    required: [true, 'Password is required'],
    select: false // Don't include in queries by default
  },
  
  // User role for access control
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  
  // Account status
  isActive: {
    type: Boolean,
    default: true
  },
  
  isVerified: {
    type: Boolean,
    default: false
  },
  
  // Two-Factor Authentication
  twoFactorAuth: {
    enabled: {
      type: Boolean,
      default: false
    },
    secret: {
      type: String,
      select: false // Keep 2FA secret private
    },
    backupCodes: [{
      code: String,
      used: {
        type: Boolean,
        default: false
      }
    }],
    lastUsed: Date
  },
  
  // OTP for email-based 2FA
  otp: {
    code: {
      type: String,
      select: false
    },
    expiresAt: {
      type: Date,
      select: false
    },
    attempts: {
      type: Number,
      default: 0,
      select: false
    }
  },
  
  // Security tracking
  security: {
    loginAttempts: {
      type: Number,
      default: 0
    },
    lockoutUntil: Date,
    passwordChangedAt: {
      type: Date,
      default: Date.now
    },
    lastLogin: {
      type: Date
    },
    lastLoginIP: String,
    failedLoginIPs: [String]
  },
  
  // Password reset
  resetPassword: {
    token: {
      type: String,
      select: false
    },
    expiresAt: {
      type: Date,
      select: false
    }
  },
  
  // Account metadata
  profile: {
    firstName: String,
    lastName: String,
    dateOfBirth: Date,
    profilePicture: String
  },
  
  // Data vault reference
  vaultId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Vault'
  },
  
  // Timestamps
  createdAt: {
    type: Date,
    default: Date.now
  },
  
  updatedAt: {
    type: Date,
    default: Date.now
  },
  
  lastActiveAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      // Remove sensitive fields from JSON output
      delete ret.passwordHash;
      delete ret.twoFactorAuth.secret;
      delete ret.otp;
      delete ret.resetPassword;
      delete ret.__v;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

// Indexes for performance
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ createdAt: -1 });
userSchema.index({ lastActiveAt: -1 });
userSchema.index({ 'security.lockoutUntil': 1 }, { sparse: true });

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.security.lockoutUntil && this.security.lockoutUntil > Date.now());
});

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  if (this.profile.firstName && this.profile.lastName) {
    return `${this.profile.firstName} ${this.profile.lastName}`;
  }
  return this.username;
});

// Pre-save middleware
userSchema.pre('save', function(next) {
  // Update the updatedAt field
  this.updatedAt = Date.now();
  
  // Update lastActiveAt if this is a login-related update
  if (this.isModified('security.lastLogin')) {
    this.lastActiveAt = Date.now();
  }
  
  next();
});

// Instance methods
userSchema.methods.toSafeObject = function() {
  const user = this.toObject();
  delete user.passwordHash;
  delete user.twoFactorAuth.secret;
  delete user.otp;
  delete user.resetPassword;
  return user;
};

// Check if account is locked
userSchema.methods.isAccountLocked = function() {
  return !!(this.security.lockoutUntil && this.security.lockoutUntil > Date.now());
};

// Increment login attempts
userSchema.methods.incrementLoginAttempts = function() {
  const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
  const lockoutTime = parseInt(process.env.LOCKOUT_TIME_MINUTES) || 15;
  
  // Increment failed attempts
  this.security.loginAttempts += 1;
  
  // Lock account if max attempts reached
  if (this.security.loginAttempts >= maxAttempts) {
    this.security.lockoutUntil = Date.now() + (lockoutTime * 60 * 1000);
  }
  
  return this.save();
};

// Reset login attempts on successful login
userSchema.methods.resetLoginAttempts = function() {
  this.security.loginAttempts = 0;
  this.security.lockoutUntil = undefined;
  this.security.lastLogin = Date.now();
  this.lastActiveAt = Date.now();
  
  return this.save();
};

// Set OTP for email-based 2FA
userSchema.methods.setOTP = function(otp) {
  const expiryMinutes = parseInt(process.env.OTP_EXPIRY_MINUTES) || 5;
  
  this.otp = {
    code: otp,
    expiresAt: new Date(Date.now() + (expiryMinutes * 60 * 1000)),
    attempts: 0
  };
  
  return this.save();
};

// Verify OTP
userSchema.methods.verifyOTP = function(providedOTP) {
  if (!this.otp || !this.otp.code) {
    return false;
  }
  
  // Check if OTP is expired
  if (this.otp.expiresAt < new Date()) {
    return false;
  }
  
  // Check if too many attempts
  if (this.otp.attempts >= 3) {
    return false;
  }
  
  // Verify OTP
  const isValid = this.otp.code === providedOTP;
  
  if (isValid) {
    // Clear OTP after successful verification
    this.otp = undefined;
  } else {
    // Increment attempts
    this.otp.attempts += 1;
  }
  
  return isValid;
};

// Static methods
userSchema.statics.findByEmail = function(email) {
  return this.findOne({ email: email.toLowerCase() });
};

userSchema.statics.findByUsername = function(username) {
  return this.findOne({ username: username.toLowerCase() });
};

userSchema.statics.findActive = function() {
  return this.find({ isActive: true });
};

userSchema.statics.findAdmins = function() {
  return this.find({ role: 'admin', isActive: true });
};
// Add this method to your User schema
userSchema.methods.toSafeObject = function() {
  const user = this.toObject();
  delete user.passwordHash;
  delete user.otp;
  delete user.resetPassword;
  return user;
};

// Export the model
const User = mongoose.model('User', userSchema);

module.exports = User;