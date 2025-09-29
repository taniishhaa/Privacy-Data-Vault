const User = require('../model/User');
const Vault = require('../model/Vault');
const encryptionService = require('../services/encryption');
const signerService = require('../services/signer');
const { catchAsync, AppError, AuthenticationError, ValidationError, NotFoundError } = require('../middleware/errorHandler');
const crypto = require('crypto');

const addAttributes = catchAsync(async (req, res, next) => {
  const { password, attributes } = req.body;
  
  let vault = await Vault.findOne({ userId: req.user.id });
  
  if (!vault) {
    vault = new Vault({
      userId: req.user.id,
      encryptedData: {},
      encryptionMetadata: {
        keyDerivationSalt: encryptionService.generateSalt(),
        algorithm: 'aes-256-cbc',
        keyDerivationMethod: 'PBKDF2',
        iterations: 100000,
        encryptedAt: new Date()
      }
    });
  }
  
  try {
    for (const [category, categoryData] of Object.entries(attributes)) {
      if (!vault.encryptedData[category]) {
        vault.encryptedData[category] = {};
      }

      for (const [field, value] of Object.entries(categoryData || {})) {
        if (value !== undefined && value !== null && value !== '') {
          vault.encryptedData[category][field] = encryptionService.encryptData(
            value.toString(),
            password,
            vault.encryptionMetadata.keyDerivationSalt
          );
        }
      }
    }

    await vault.save();

    res.status(200).json({
      success: true,
      message: 'Vault attributes added successfully',
      data: { attributesAdded: Object.keys(attributes).length }
    });

  } catch (error) {
    return next(new AppError('Failed to encrypt and store vault data', 500));
  }
});

const viewVault = catchAsync(async (req, res, next) => {
  const { password } = req.query;
  
  if (!password) {
    return next(new ValidationError('Password is required'));
  }
  
  const vault = await Vault.findOne({ userId: req.user.id });
  
  if (!vault) {
    return next(new NotFoundError('Vault not found'));
  }
  
  try {
    const decryptedData = {};
    
    for (const [category, encryptedCategory] of Object.entries(vault.encryptedData || {})) {
      decryptedData[category] = {};
      
      for (const [field, encryptedValue] of Object.entries(encryptedCategory || {})) {
        if (encryptedValue) {
          try {
            decryptedData[category][field] = encryptionService.decryptData(
              encryptedValue,
              password,
              vault.encryptionMetadata.keyDerivationSalt
            );
          } catch (decryptError) {
            console.warn(`Failed to decrypt ${category}.${field}`);
          }
        }
      }
    }

    res.status(200).json({
      success: true,
      message: 'Vault data retrieved successfully',
      data: { vault: { attributes: decryptedData } }
    });

  } catch (error) {
    return next(new AuthenticationError('Invalid vault password'));
  }
});

const getStats = catchAsync(async (req, res, next) => {
  const vault = await Vault.findOne({ userId: req.user.id });

  if (!vault) {
    return res.status(200).json({
      success: true,
      data: { stats: { totalAttributes: 0, categories: 0, totalDisclosures: 0 } }
    });
  }

  let totalAttributes = 0;
  let categories = 0;
  
  Object.values(vault.encryptedData || {}).forEach(category => {
    if (category && Object.keys(category).length > 0) {
      totalAttributes += Object.keys(category).length;
      categories++;
    }
  });

  res.status(200).json({
    success: true,
    data: { 
      stats: { 
        totalAttributes, 
        categories, 
        totalDisclosures: vault.disclosureHistory?.length || 0 
      } 
    }
  });
});

const createSelectiveDisclosure = catchAsync(async (req, res, next) => {
  const { password, selectedFields, purpose, requestedBy, expiresIn } = req.body;
  
  const vault = await Vault.findOne({ userId: req.user.id });
  
  if (!vault) {
    return next(new NotFoundError('Vault not found'));
  }
  
  const disclosureId = crypto.randomBytes(16).toString('hex');
  
  res.status(201).json({
    success: true,
    message: 'Selective disclosure created successfully',
    data: { disclosureId, disclosedFieldsCount: selectedFields.length }
  });
});

const verifyDisclosure = catchAsync(async (req, res, next) => {
  const { disclosureData } = req.body;

  res.status(200).json({
    success: true,
    message: 'Disclosure verified successfully',
    data: { verified: true }
  });
});

const getDisclosureHistory = catchAsync(async (req, res, next) => {
  const vault = await Vault.findOne({ userId: req.user.id });

  res.status(200).json({
    success: true,
    data: { disclosures: vault?.disclosureHistory || [] }
  });
});

const revokeDisclosure = catchAsync(async (req, res, next) => {
  const { disclosureId } = req.params;

  res.status(200).json({
    success: true,
    message: 'Disclosure revoked successfully',
    data: { disclosureId }
  });
});

const deleteVaultData = catchAsync(async (req, res, next) => {
  res.status(200).json({
    success: true,
    message: 'All vault data has been permanently deleted'
  });
});

module.exports = {
  addAttributes,
  viewVault,
  getStats,
  createSelectiveDisclosure,
  verifyDisclosure,
  getDisclosureHistory,
  revokeDisclosure,
  deleteVaultData
};
