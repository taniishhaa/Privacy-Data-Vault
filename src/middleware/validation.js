const { body, param, validationResult } = require('express-validator');
const { ValidationError } = require('./errorHandler');

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => error.msg);
    return next(new ValidationError(errorMessages.join('. ')));
  }
  next();
};

const validateRegistration = [
  body('username').trim().isLength({ min: 3, max: 30 }).withMessage('Username must be between 3 and 30 characters'),
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email address'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.password) throw new Error('Passwords do not match');
    return true;
  }),
  handleValidationErrors
];

const validateLogin = [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email address'),
  body('password').notEmpty().withMessage('Password is required'),
  handleValidationErrors
];

const validateOTP = [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email address'),
  body('otp').isLength({ min: 6, max: 6 }).isNumeric().withMessage('OTP must be a 6-digit number'),
  handleValidationErrors
];

const validatePasswordResetRequest = [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email address'),
  handleValidationErrors
];

const validatePasswordReset = [
  body('token').notEmpty().withMessage('Reset token is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
  body('confirmPassword').custom((value, { req }) => {
    if (value !== req.body.newPassword) throw new Error('Passwords do not match');
    return true;
  }),
  handleValidationErrors
];

const validateProfileUpdate = [
  body('profile.firstName').optional().trim().isLength({ min: 1, max: 50 }).withMessage('First name must be between 1 and 50 characters'),
  body('profile.lastName').optional().trim().isLength({ min: 1, max: 50 }).withMessage('Last name must be between 1 and 50 characters'),
  handleValidationErrors
];

const validateChangePassword = [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters long'),
  body('confirmNewPassword').custom((value, { req }) => {
    if (value !== req.body.newPassword) throw new Error('Passwords do not match');
    return true;
  }),
  handleValidationErrors
];

const validate2FAToken = [
  body('password').notEmpty().withMessage('Password is required for 2FA setup'),
  handleValidationErrors
];

const validateVaultAttributes = [
  body('password').notEmpty().withMessage('Vault password is required'),
  body('attributes').isObject().withMessage('Attributes must be an object'),
  handleValidationErrors
];

const validateSelectiveDisclosure = [
  body('password').notEmpty().withMessage('Vault password is required'),
  body('selectedFields').isArray({ min: 1 }).withMessage('At least one field must be selected'),
  body('purpose').trim().isLength({ min: 5, max: 200 }).withMessage('Purpose must be between 5 and 200 characters'),
  handleValidationErrors
];

const validateDisclosureVerification = [
  body('disclosureData').isObject().withMessage('Valid disclosure data is required'),
  handleValidationErrors
];

const validateObjectId = (paramName) => [
  param(paramName).isLength({ min: 8 }).withMessage(`Valid ${paramName} is required`),
  handleValidationErrors
];

module.exports = {
  validateRegistration,
  validateLogin,
  validateOTP,
  validatePasswordResetRequest,
  validatePasswordReset,
  validateProfileUpdate,
  validateChangePassword,
  validate2FAToken,
  validateVaultAttributes,
  validateSelectiveDisclosure,
  validateDisclosureVerification,
  validateObjectId,
  handleValidationErrors
};
