const express = require('express');
const authController = require('../controllers/auth.controller');
const userController = require('../controllers/user.controller');
const accountController = require('../controllers/account.controller');

const router = express.Router();

/**
 * AUTHENTICATION
 */
router.post('/signup', authController.signup);
router
  .route('/email-confirmation/:emailToken')
  .get(authController.verifyEmail)
  .delete(authController.deletePendingUser);
router.post(
  '/resend-email-confirm',
  authController.reSendEmailProtect,
  authController.reSendEmailConfirm
);
router.post('/login', authController.login);
router.get('/logout', authController.logout);
router.post('/forgot-password', authController.forgotPassword);
router.patch('/reset-password/:token', authController.resetPassword);

/**
 * PROTECTED ROUTES
 */
router.use(authController.protect);
router.route('/me').get(userController.getMe).patch(userController.updateMe);
router.patch('/me/deactivate', userController.deactivateMe);
router.post(
  '/me/delete',
  authController.checkPassword,
  userController.deleteMe
);
router.patch('/me/update-password', authController.updatePassword);

/**
 * ACCOUNT RELATED ROUTES
 */
router
  .route('/account')
  .put(accountController.handleImageName, accountController.addAccount);
router
  .route('/account/:accountId')
  .get(accountController.getAccountPassword)
  .patch(accountController.handleImageName, accountController.updateAccount)
  .delete(accountController.deleteAccount);

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
