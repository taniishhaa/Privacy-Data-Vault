const express = require('express');
const router = express.Router();
const vaultController = require('../controllers/vaultController');
const { authenticateToken, require2FA, sensitiveOpLimiter } = require('../middleware/auth');
const rateLimiter = require('../middleware/rateLimiter');
const {
  validateVaultAttributes,
  validateSelectiveDisclosure,
  validateDisclosureVerification,
  validateObjectId
} = require('../middleware/validation');

/**
 * Vault Management Routes
 * All routes for encrypted data storage, retrieval, and selective disclosure
 */

// Protected vault routes (require authentication)
router.use(authenticateToken);

/**
 * POST /api/vault/add
 * Add or update encrypted attributes in vault
 */
router.post('/add',
  rateLimiter.vaultOperations,
  validateVaultAttributes,
  vaultController.addAttributes
);

/**
 * GET /api/vault/view
 * View decrypted vault contents (requires password)
 */
router.get('/view',
  rateLimiter.vaultOperations,
  vaultController.viewVault
);

/**
 * GET /api/vault/stats
 * Get vault statistics without decrypting data
 */
router.get('/stats',
  vaultController.getStats
);

/**
 * POST /api/vault/share
 * Create selective disclosure document
 */
router.post('/share',
  rateLimiter.disclosure,
  validateSelectiveDisclosure,
  vaultController.createSelectiveDisclosure
);

/**
 * POST /api/vault/verify
 * Verify selective disclosure document (public endpoint - no auth required)
 */
router.post('/verify',
  rateLimiter.verification,
  validateDisclosureVerification,
  vaultController.verifyDisclosure
);

/**
 * GET /api/vault/disclosures
 * Get disclosure history for current user
 */
router.get('/disclosures',
  vaultController.getDisclosureHistory
);

/**
 * POST /api/vault/revoke/:disclosureId
 * Revoke a specific disclosure
 */
router.post('/revoke/:disclosureId',
  rateLimiter.vaultOperations,
  validateObjectId('disclosureId'),
  vaultController.revokeDisclosure
);

/**
 * DELETE /api/vault/data
 * Delete all vault data (dangerous operation)
 */
router.delete('/data',
  rateLimiter.authStrict,
  require2FA,
  sensitiveOpLimiter(3, 60 * 60 * 1000), // Max 3 attempts per hour
  vaultController.deleteVaultData
);

/**
 * GET /api/vault/export
 * Export encrypted vault data for backup
 */
router.get('/export',
  rateLimiter.dataExport,
  vaultController.exportVaultData || ((req, res) => {
    res.status(501).json({
      success: false,
      message: 'Export functionality not yet implemented'
    });
  })
);

/**
 * POST /api/vault/import
 * Import vault data from backup
 */
router.post('/import',
  rateLimiter.authStrict,
  require2FA,
  vaultController.importVaultData || ((req, res) => {
    res.status(501).json({
      success: false,
      message: 'Import functionality not yet implemented'
    });
  })
);

module.exports = router;