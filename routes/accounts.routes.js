const express = require('express');
const authController = require('../controllers/auth.controller');
const accountController = require('../controllers/account.controller');

const router = express.Router();

router.use(authController.protect);
router
  .route('/')
  .get(accountController.getAccounts)
  .put(accountController.handleImageName, accountController.addAccount);
router
  .route('/:accountId')
  .post(authController.checkPin, accountController.getAccountPassword)
  .patch(accountController.handleImageName, accountController.updateAccount)
  .delete(accountController.deleteAccount);

module.exports = router;
