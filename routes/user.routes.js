const express = require('express');
const authController = require('../controllers/auth.controller');
const userController = require('../controllers/user.controller');

const router = express.Router();

/**
 * AUTHENTICATION
 */
router.post('/signup', authController.signup);
router
  .route('/email-confirmation/:emailToken')
  .get(authController.isEmailTokenValid)
  .post(authController.verifyEmail)
  .delete(authController.deletePendingUser);
router.post(
  '/resend-email-confirm',
  authController.reSendEmailProtect,
  authController.reSendEmailConfirm
);
router.post('/login', authController.login, authController.loginUnknownIP);
router.get('/logout', authController.logout);
router.post('/forgot-password', authController.forgotPassword);
router.patch('/reset-password/:token', authController.resetPassword);

/**
 * PROTECTED ROUTES
 */
router.use(authController.protect, authController.ipProtect);
router.route('/me').get(userController.getMe).patch(userController.updateMe);
router.patch('/me/deactivate', userController.deactivateMe);
router.post(
  '/me/delete',
  authController.checkPassword,
  userController.deleteMe
);
router.patch('/me/update-password', authController.updatePassword);
router.patch(
  '/me/reset-pin',
  authController.checkPassword,
  authController.resetPin
);
router.patch('/me/remove-ip', authController.removeIp);

/**
 * ADMIN ROUTES
 */
router.use(authController.restrictTo(['admin']));
router
  .route('/')
  .get(userController.getAllUsers)
  .post(userController.createUser);
router
  .route('/:id')
  .get(userController.getUser)
  .patch(userController.updateUser)
  .delete(userController.deleteUser);

module.exports = router;
