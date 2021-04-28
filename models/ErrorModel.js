const mongoose = require('mongoose');

const errorSchema = new mongoose.Schema({
  occurred: {
    type: Date,
    default: Date.now(),
  },
  errorType: {
    type: String,
    default: 'unknown',
  },
  errorCode: Number,
  errorMesage: String,
  errorStack: String,
});

const ErrorModel = mongoose.model('Error', errorSchema);

module.exports = ErrorModel;
