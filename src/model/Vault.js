const mongoose = require('mongoose');

const vaultSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  encryptedData: {
    personalInfo: { type: Object, default: {} },
    contactInfo: { type: Object, default: {} },
    identificationInfo: { type: Object, default: {} },
    financialInfo: { type: Object, default: {} },
    healthInfo: { type: Object, default: {} },
    educationInfo: { type: Object, default: {} }
  },
  encryptionMetadata: {
    keyDerivationSalt: String,
    algorithm: { type: String, default: 'aes-256-cbc' },
    keyDerivationMethod: { type: String, default: 'PBKDF2' },
    iterations: { type: Number, default: 100000 },
    encryptedAt: Date,
    lastAccessed: Date
  },
  disclosureHistory: [{
    disclosureId: String,
    purpose: String,
    requestedBy: String,
    disclosedFields: [String],
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date,
    verificationStatus: { type: String, default: 'pending' },
    revokedAt: Date,
    revokeReason: String
  }]
}, {
  timestamps: true
});

module.exports = mongoose.model('Vault', vaultSchema);
