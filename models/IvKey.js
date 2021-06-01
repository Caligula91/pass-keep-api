const mongoose = require('mongoose');

const ivSchema = new mongoose.Schema({
  accountId: {
    required: true,
    type: mongoose.Schema.ObjectId,
    unique: true,
    ref: 'User.accounts',
  },
  iv: {
    type: String,
    required: true,
  },
});

const IvKey = mongoose.model('IvKey', ivSchema);

module.exports = IvKey;
