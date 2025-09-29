const bcrypt = require('bcrypt');
const crypto = require('crypto');

const SALT_ROUNDS = 12;
const ALGORITHM = 'aes-256-cbc';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;

// Hash password
const hashPassword = async (password) => {
  return await bcrypt.hash(password, SALT_ROUNDS);
};

// Verify password
const verifyPassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

// Sync version for backup codes
const hashPasswordSync = (password) => {
  return bcrypt.hashSync(password, SALT_ROUNDS);
};

const verifyPasswordSync = (password, hash) => {
  return bcrypt.compareSync(password, hash);
};

// Generate random key
const generateKey = () => {
  return crypto.randomBytes(KEY_LENGTH);
};

// Generate IV
const generateIV = () => {
  return crypto.randomBytes(IV_LENGTH);
};

// Generate salt
const generateSalt = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Derive key from password
const deriveKeyFromPassword = (password, salt) => {
  return crypto.pbkdf2Sync(password, salt, 100000, KEY_LENGTH, 'sha256');
};

// Encrypt data
const encrypt = (text, key) => {
  const iv = generateIV();
  const cipher = crypto.createCipher(ALGORITHM, key);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    encrypted,
    iv: iv.toString('hex')
  };
};

// Decrypt data
const decrypt = (encryptedHex, ivHex, key) => {
  const decipher = crypto.createDecipher(ALGORITHM, key);
  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

// Encrypt user attributes
const encryptUserAttributes = (attributes, password) => {
  const salt = generateSalt();
  const key = deriveKeyFromPassword(password, salt);
  
  const encryptedAttributes = {};
  
  Object.entries(attributes).forEach(([field, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      encryptedAttributes[field] = encrypt(JSON.stringify(value), key);
    }
  });
  
  return {
    encryptedAttributes,
    metadata: {
      salt,
      algorithm: ALGORITHM,
      keyDerivationMethod: 'PBKDF2',
      iterations: 100000
    }
  };
};

// Decrypt user attributes
const decryptUserAttributes = (encryptedData, password) => {
  const { encryptedAttributes, metadata } = encryptedData;
  const key = deriveKeyFromPassword(password, metadata.salt);
  
  const decryptedAttributes = {};
  
  Object.entries(encryptedAttributes).forEach(([field, encryptedValue]) => {
    try {
      const decrypted = decrypt(encryptedValue.encrypted, encryptedValue.iv, key);
      decryptedAttributes[field] = JSON.parse(decrypted);
    } catch (error) {
      console.warn(`Failed to decrypt field ${field}:`, error.message);
    }
  });
  
  return decryptedAttributes;
};

// Simple encrypt/decrypt for vault
const encryptData = (data, password, salt) => {
  const key = deriveKeyFromPassword(password, salt);
  return encrypt(data, key);
};

const decryptData = (encryptedData, password, salt) => {
  const key = deriveKeyFromPassword(password, salt);
  return decrypt(encryptedData.encrypted, encryptedData.iv, key);
};

// Password strength validation
const validatePasswordStrength = (password) => {
  const issues = [];
  
  if (password.length < 8) issues.push('At least 8 characters');
  if (!/[A-Z]/.test(password)) issues.push('One uppercase letter');
  if (!/[a-z]/.test(password)) issues.push('One lowercase letter');
  if (!/\d/.test(password)) issues.push('One number');
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) issues.push('One special character');
  
  return {
    isValid: issues.length === 0,
    issues
  };
};

module.exports = {
  hashPassword,
  verifyPassword,
  hashPasswordSync,
  verifyPasswordSync,
  generateKey,
  generateIV,
  generateSalt,
  deriveKeyFromPassword,
  encrypt,
  decrypt,
  encryptUserAttributes,
  decryptUserAttributes,
  encryptData,
  decryptData,
  validatePasswordStrength
};
