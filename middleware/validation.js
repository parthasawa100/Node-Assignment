const { body, validationResult } = require('express-validator');

const validateAdminCreation = [
  body('email').isEmail().withMessage('Invalid email format'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
];

const validateUserCreation = [
  body('email').isEmail().withMessage('Invalid email format'),
  body('phone').isMobilePhone().withMessage('Invalid phone number'),
  body('name').notEmpty().withMessage('Name is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
];

const validateLogin = [
  body('email').isEmail().withMessage('Invalid email format'),
  body('password').notEmpty().withMessage('Password is required'),
];

const validateProfileModification = [
  body('name').optional().notEmpty().withMessage('Name is required'),
];

const validateInitialAdminCreation = [
  body('email').isEmail().withMessage('Invalid email format'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
];

const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

module.exports = {
  validateAdminCreation,
  validateUserCreation,
  validateLogin,
  validateProfileModification,
  validateInitialAdminCreation,
  validateRequest,
};
