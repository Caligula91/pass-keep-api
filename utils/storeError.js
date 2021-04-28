const ErrorModel = require('../models/ErrorModel');

module.exports = async (type, error) => {
  await ErrorModel.create({
    errorType: type,
    errorCode: error.code * 1 || error.statusCode * 1 || 500,
    errorMessage: error.message,
    errorStack: error,
  });
};
