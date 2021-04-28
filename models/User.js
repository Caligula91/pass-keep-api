const crypto = require('crypto');
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcrypt');
const { allImagesSet } = require('../utils/images');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required for creating a new user'],
    validate: {
      validator: function (name) {
        return validator.isAlpha(name, 'sr-RS@latin', { ignore: ' ' });
      },
      message: 'Name can contain only letters',
    },
    minlength: [3, 'Name must contain at least 3 character'],
    maxlength: [30, "Name can't contain more than 30 characters"],
  },
  password: {
    type: String,
    required: [true, 'Password is required for creating a new user'],
    validate: [
      validator.isAlphanumeric,
      'Password can contain only numbers and letters',
    ],
    minlength: [8, 'Password must contain at least 8 characters'],
    select: false,
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      // This only works on CREATE and SAVE!!!
      validator: function (el) {
        return el === this.password;
      },
      message: 'Passwords are not the same!',
    },
  },
  passwordChangedAt: Date,
  passwordResetToken: {
    type: String,
    select: false,
  },
  passwordResetExpires: {
    type: Date,
    select: false,
  },
  email: {
    type: String,
    unique: true,
    lowercase: true,
    required: [true, 'Email is required for creating a new user'],
    validate: [validator.isEmail, 'Invalid email format'],
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },
  confirmationToken: String,
  confirmationTokenExpires: Date,
  nextReSendPosible: Date,
  reSendCount: Number,
  status: {
    type: String,
    enum: ['Pending', 'Active', 'Inactive', 'Banned'],
    default: 'Pending',
  },
  userCreated: {
    type: Date,
    default: new Date(Date.now()),
  },
  accounts: [
    {
      name: {
        type: String,
        required: [true, 'Account name is required'],
      },
      userEmail: {
        type: String,
      },
      password: {
        type: String,
        required: [
          true,
          'Please provide password for account, whole point of this is to store password',
        ],
        select: false,
      },
      iv: {
        type: String,
        required: true,
        select: false,
      },
      //
      image: {
        type: String,
        default: function () {
          const firstLetter = this.name.charAt(0);
          return firstLetter.match(/[A-Za-z]/)
            ? `${firstLetter}.png`
            : `default.png`;
        },
        validate: {
          validator: function (img) {
            return allImagesSet.has(img);
          },
          message:
            'Image path not found in database. Do not set image and server will automatically set image for you',
        },
      },
      modified: {
        type: Date,
        default: new Date(Date.now()),
      },
    },
  ],
  lastCheckedAccount: String,
  lastCheckedAccountDate: Date,
});

/**
 * PASSWORD RELATED
 */
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();
  this.passwordChangedAt = Date.now() - 1000;
  next();
});

/**
 * TRIM NAME AND REMOVE EXTRA WHITESPACE
 */
userSchema.pre('save', function (next) {
  let name = this.get('name');
  if (name) {
    name = name.trim().replace(/\s{2,}/g, ' ');
    this.set('name', name);
  }
  next();
});

userSchema.pre(/update/i, function (next) {
  let name = this.get('name');
  if (name) {
    name = name.trim().replace(/\s{2,}/g, ' ');
    this.setUpdate({ $set: { name } });
  }
  next();
});

/**
 * REMOVE __V FROM RESPONSE
 */
userSchema.pre(/^find/, function (next) {
  this.select('-__v');
  next();
});

/**
 * INSTANCE METHODS
 */
userSchema.methods.isCorrectPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.isPasswordValid = function (tokenIssuedAt) {
  if (!this.passwordChangedAt) return true;
  // must divide by 1000 because getTime() returns miliseconds and jwt.iat is in seconds
  const changedTime = parseInt(this.passwordChangedAt.getTime(), 10);
  return changedTime < tokenIssuedAt * 1000;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(24).toString('hex');
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  return resetToken;
};

userSchema.methods.getEmailConfirmToken = function () {
  const emailToken = crypto.randomBytes(24).toString('hex');
  this.confirmationToken = crypto
    .createHash('sha256')
    .update(emailToken)
    .digest('hex');
  this.confirmationTokenExpires = Date.now() + 10 * 60 * 1000;
  return emailToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
