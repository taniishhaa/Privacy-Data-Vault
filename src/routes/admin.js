const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { authenticateToken, requireAdmin } = require('../middleware/auth');
const rateLimiter = require('../middleware/rateLimiter');

/**
 * Admin Routes - All routes require admin authentication
 */

// Apply authentication and admin check to all routes
router.use(authenticateToken);
router.use(requireAdmin);

/**
 * GET /api/admin/stats
 * Get system-wide statistics
 */
router.get('/stats', adminController.getStats);

/**
 * GET /api/admin/users
 * Get paginated list of users
 */
router.get('/users', adminController.getUsers);

/**
 * GET /api/admin/users/:userId
 * Get specific user details
 */
router.get('/users/:userId', adminController.getUserById);

/**
 * PUT /api/admin/users/:userId
 * Update user information
 */
router.put('/users/:userId', rateLimiter.admin, adminController.updateUser);

/**
 * GET /api/admin/vaults
 * Get vault overview
 */
router.get('/vaults', adminController.getVaults);

/**
 * GET /api/admin/audit
 * Get system audit logs
 */
router.get('/audit', adminController.getAuditLog);

/**
 * GET /api/admin/disclosures
 * Get all selective disclosures
 */
router.get('/disclosures', adminController.getAllDisclosures);

/**
 * GET /api/admin/security
 * Get security overview
 */
router.get('/security', adminController.getSecurityOverview);

/**
 * POST /api/admin/maintenance
 * Perform system maintenance
 */
router.post('/maintenance', rateLimiter.admin, adminController.performMaintenance);

module.exports = router;
