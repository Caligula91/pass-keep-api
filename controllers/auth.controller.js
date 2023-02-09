const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const hash = require('object-hash');
const User = require('../models/User');
const catchAsync = require('../utils/catchAsync');
const Email = require('../utils/Email');
const AppError = require('../utils/AppError');
const storeError = require('../utils/storeError');

const signToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '90d',
  });

const sendResponseWithToken = (user, req, res, statusCode) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      // 1 hour
      Date.now() + 2160 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
    // secure: process.env.NODE_ENV === 'production',
  };
  res.cookie('jwt', token, cookieOptions);

  // setting to undefined sensitive data
  user.password = undefined;
  user.status = undefined;

  // sending response
  res.status(statusCode).json({
    status: 'success',
    token,
    tokenExpires: cookieOptions.expires,
    user,
  });
};

/**
 * CHECK TRUSTED DEVICE
 */
const isTrustedDevice = (device, req) =>
  device.deviceId === hash(req.useragent);

/**
 * GET UNIQUE VALUE FROM USERAGENT INFO
 */
const getDeviceId = (useragent) => hash(useragent);

exports.restrictTo = (roles) => (req, res, next) => {
  if (roles.includes(req.user.role)) return next();
  next(new AppError('You are unauthorized to access this route.', 403));
};

/**
 * PROTECT ROUTES
 */
exports.protect = catchAsync(async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }
  if (!token) return next(new AppError('You are not logged in.', 401));
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const user = await User.findById(decoded.id).select('+passwordChangedAt');
  if (!user || user.status === 'Inactive') {
    // PURGE INVALID TOKEN
    res.cookie('jwt', 'dummy', {
      expires: new Date(Date.now() + 1000),
      httpOnly: true,
    });
    return next(new AppError('Invalid token, please login again.', 401));
  }
  if (user.status === 'Banned')
    return next(
      new AppError(
        'Account is banned, contact admin for more information.',
        401
      )
    );
  if (user.status === 'Pending')
    return next(new AppError('User is not verified', 401));
  if (!user.isPasswordValid(decoded.iat))
    return next(
      new AppError(
        'You are using old password, please login and try again.',
        401
      )
    );
  user.passwordChangedAt = undefined;
  user.status = undefined;
  req.user = user;
  next();
});

/**
 * PROTECT IP
 */
exports.ipProtect = (req, res, next) => {
  const trustedDevice = req.user.loggedDevices
    ? req.user.loggedDevices.find((device) => isTrustedDevice(device, req))
    : false;
  if (trustedDevice) {
    // set current device on req object
    req.currentDevice = trustedDevice;

    // update last activity
    // no need to await results, update in the background
    // tolerate 1 min diff from last activity to increase performance
    if (Date.now() > trustedDevice.lastActivity.getTime() + 1 * 60 * 1000) {
      User.findOneAndUpdate(
        {
          _id: req.user.id,
          'loggedDevices._id': trustedDevice.id,
        },
        {
          'loggedDevices.$.lastActivity': Date.now(),
        },
        (err) => {
          if (err) storeError('lastActivity', err).catch(() => {});
        }
      );
    }
    return next();
  }
  next(
    new AppError('Your device is not recognised, please log in again.', 403)
  );
};

/**
 * REMOVE LOGGED DEVICE
 */
exports.removeLoggedDevice = catchAsync(async (req, res, next) => {
  const { loggedDeviceId } = req.params;
  const user = await User.findOneAndUpdate(
    {
      _id: req.user.id,
      'loggedDevices._id': loggedDeviceId,
    },
    {
      $pull: { loggedDevices: { _id: loggedDeviceId } },
    },
    {
      new: true,
    }
  );
  if (!user) return next(new AppError('Device not found', 404));
  res.status(200).json({
    status: 'success',
    message: 'Device removed from logged devices.',
    user,
    currentDevice: req.currentDevice,
  });
});

/**
 * SIGNUP
 */
exports.signup = catchAsync(async (req, res, next) => {
  const { name, password, passwordConfirm, email } = req.body;
  const user = new User({ name, password, passwordConfirm, email });
  const emailToken = user.getEmailConfirmToken();
  await user.save();
  user.password = undefined;
  const url = `${process.env.WEBSITE_DOMAIN}email-confirmation/${emailToken}`;
  try {
    await new Email(user, url).sendConfirmation();
  } catch (error) {
    await User.findByIdAndDelete(user.id);
    storeError('email', error).catch(() => {});
    return next(error);
  }
  res.status(201).json({
    status: 'success',
    message: `We sent an email to ${email} to make sure you own it. Please check your inbox and verify your email address.`,
  });
});

/**
 * VERIFY EMAIL
 */
exports.isEmailTokenValid = catchAsync(async (req, res, next) => {
  const { emailToken } = req.params;
  // find user with email token
  const confirmationToken = crypto
    .createHash('sha256')
    .update(emailToken)
    .digest('hex');
  const user = await User.findOne({
    confirmationToken,
    confirmationTokenExpires: { $gt: Date.now() },
  });
  if (!user) return next(new AppError('Invalid email token.', 400));
  res.status(200).json({
    status: 'success',
    message: 'valid email token',
  });
});

exports.verifyEmail = catchAsync(async (req, res, next) => {
  const { pin, pinConfirm } = req.body;
  const { emailToken } = req.params;

  // find user with email token
  const confirmationToken = crypto
    .createHash('sha256')
    .update(emailToken)
    .digest('hex');
  let user = await User.findOne({
    confirmationToken,
    confirmationTokenExpires: { $gt: Date.now() },
  }).select('-password -passwordConfirm');
  if (!user) return next(new AppError('Invalid email token.', 400));

  // set new pin and set status to Active
  user.confirmationToken = undefined;
  user.confirmationTokenExpires = undefined;
  user.nextReSendPosible = undefined;
  user.reSendCount = undefined;
  user.status = 'Active';
  user.pin = pin;
  user.pinConfirm = pinConfirm;

  // add logged device to loggedDevices
  user.loggedDevices = [
    {
      deviceId: getDeviceId(req.useragent),
      ip: req.ipInfo.ip,
      location:
        req.ipInfo.country && req.ipInfo.city
          ? `${req.ipInfo.city}, ${req.ipInfo.country}`
          : 'unknown',
      os: req.useragent.os,
      platform: req.useragent.platform,
      browser: req.useragent.browser,
      lastActivity: new Date(Date.now()),
    },
  ];

  // update user with new data
  user = await user.save();

  // send email
  const url = `${process.env.WEBSITE_DOMAIN}`;
  try {
    await new Email(user, url).sendWelcome();
  } catch (error) {
    storeError('email', error).catch(() => {});
  }
  sendResponseWithToken(user, req, res, 200);
});

exports.reSendEmailConfirm = catchAsync(async (req, res, next) => {
  const { user } = req;
  const emailToken = user.getEmailConfirmToken();
  await user.save({ validateModifiedOnly: true });
  const url = `${process.env.WEBSITE_DOMAIN}email-confirmation/${emailToken}`;
  try {
    await new Email(user, url).sendConfirmation();
  } catch (error) {
    storeError('email', error).catch(() => {});
    return next(error);
  }
  res.status(200).json({
    status: 'success',
    message: `Email sent again to ${user.email} as you requested. Check spam folder this time!`,
  });
});

exports.reSendEmailProtect = catchAsync(async (req, res, next) => {
  const { email } = req.body;
  const user = await User.findOne({ email }).select('+status');
  if (!user) return next(new AppError("User doesn't exists", 404));
  if (user.status !== 'Pending')
    return next(new AppError('User email address is verified', 403));

  if (user.reSendCount > 6) {
    return next(
      new AppError(
        'You requested to many emails to be sent, and you can not request any more. Please contact support if you are having problems.',
        403
      )
    );
  }

  if (user.nextReSendPosible) {
    const nextReSendms = user.nextReSendPosible.getTime();
    if (nextReSendms >= Date.now()) {
      const timeToWait = Math.ceil((nextReSendms - Date.now()) / 1000 / 60);
      return next(
        new AppError(
          `You reached limit, try again in ${timeToWait} minutes.`,
          403
        )
      );
    }
  }
  if (!user.reSendCount) user.reSendCount = 0;
  user.reSendCount += 1;
  user.nextReSendPosible = new Date(
    Date.now() + user.reSendCount * 10 * 60 * 1000
  );
  req.user = user;
  next();
});

exports.deletePendingUser = catchAsync(async (req, res, next) => {
  const { emailToken } = req.params;
  const confirmationToken = crypto
    .createHash('sha256')
    .update(emailToken)
    .digest('hex');
  const user = await User.findOneAndDelete({
    confirmationToken,
    status: 'Pending',
  });
  if (!user) return next(new AppError('User not found.', 404));
  res.status(204).json({
    status: 'success',
  });
});

/**
 * LOGIN
 */
exports.login = catchAsync(async (req, res, next) => {
  // check if email and password are provided
  const { email, password } = req.body;
  if (!email || !password)
    return next(new AppError('Please provide email and password', 400));

  // find user with provided email
  const user = await User.findOne({ email }).select('+password +status');
  if (!user) return next(new AppError('Incorrect email or password.', 400));

  // check password
  const correctPassword = await user.isCorrectPassword(password, user.password);
  if (!correctPassword)
    return next(new AppError('Incorrect email or password.', 400));

  // respond accordingly to user status
  switch (user.status) {
    case 'Banned': {
      return next(
        new AppError('User is banned, contact admin for more information.', 403)
      );
    }
    case 'Pending': {
      return next(new AppError('Please Verify Your Email!', 403));
    }
    case 'Inactive': {
      req.userData = { user, inactive: true };
      next();
      break;
    }
    case 'Active': {
      // check if ip is trusted
      const trustedDevice = user.loggedDevices
        ? user.loggedDevices.find((device) => isTrustedDevice(device, req))
        : false;
      if (trustedDevice) sendResponseWithToken(user, req, res, 200);
      else {
        req.userData = { user };
        next();
      }
      break;
    }
    default: {
      return next(
        new AppError('Problem with database, please contact admin.', 500)
      );
    }
  }
});

/**
 * TRIGGERS ONLY WHEN USER ACCESS FROM NEW IP
 * STATUS CODE 202 FOR UNFINISHED LOGIN
 */
exports.loginUnknownIP = catchAsync(async (req, res, next) => {
  const { user } = req.userData;
  if (!user) return next(new AppError('User not found', 404));

  // If guard code is provided, then check if its valid
  if (req.body.guardCode) {
    // check if guard code is valid
    const encryptedGuardCode = crypto
      .createHash('sha256')
      .update(req.body.guardCode)
      .digest('hex');
    if (
      encryptedGuardCode === user.guardCode &&
      user.guardCodeExpires > new Date(Date.now())
    ) {
      // unset guard code and add ip to whitelist
      const updateOperators = {
        $unset: { guardCode: '', guardCodeExpires: '' },
        $push: {
          loggedDevices: {
            deviceId: getDeviceId(req.useragent),
            ip: req.ipInfo.ip,
            location:
              req.ipInfo.country && req.ipInfo.city
                ? `${req.ipInfo.city}, ${req.ipInfo.country}`
                : 'unknown',
            os: req.useragent.os,
            platform: req.useragent.platform,
            browser: req.useragent.browser,
            lastActivity: new Date(Date.now()),
          },
        },
      };

      // if user is activting again then send email and change status to Active
      if (req.userData.inactive) {
        try {
          const url = `${process.env.WEBSITE_DOMAIN}`;
          await new Email(user, url).sendWelcomeBack();
        } catch (error) {
          storeError('email', error).catch(() => {});
        }
        updateOperators.$set = { status: 'Active' };
      }

      // update user
      const updatedUser = await User.findByIdAndUpdate(
        user.id,
        updateOperators,
        { new: true }
      );
      sendResponseWithToken(updatedUser, req, res, 200);
    } else {
      return next(new AppError('Invalid Guard Code', 400));
    }

    // if guard code is not provided, then server will attempt to send new one
  } else {
    // check if user already has guard code and if not expired yet
    if (user.guardCode && new Date(Date.now()) < user.guardCodeExpires) {
      return res.status(202).json({
        status: 'success',
        message: `We already sent you guard code. Check your inbox and enter guard code to login. If u did not receive email, try again in ${Math.ceil(
          (user.guardCodeExpires.getTime() - Date.now()) / 1000 / 60
        )} minutes`,
      });
    }

    // genereate guard code data (guardCode, guardCodeExpires, encryptedGuardCode)
    const guardCodeData = user.getGuardCodeData();

    // update user with generated guard code
    await User.findByIdAndUpdate(user.id, {
      guardCode: guardCodeData.encryptedGuardCode,
      guardCodeExpires: guardCodeData.guardCodeExpires,
    });

    // send email to user with guard code
    try {
      const ipData = {
        platform: req.useragent.platform,
        ip: req.ipInfo.ip,
        country: req.ipInfo.country,
        guardCode: guardCodeData.guardCode,
      };
      const url = `${process.env.WEBSITE_DOMAIN}`;
      await new Email(user, url, ipData).sendGuardCode();
      res.status(202).json({
        status: 'success',
        message:
          'Your device is not recognised. We sent guard code to your email. Please enter guard code to finish login',
      });
    } catch (error) {
      storeError('email', error).catch(() => {});
      // remove guard code from db if fail to send email
      await User.findByIdAndUpdate(user.id, {
        $unset: { guardCode: '', guardCodeExpires: '' },
      });
      next(error);
    }
  }
});

exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 1000),
    httpOnly: true,
  });
  res.status(200).json({ status: 'success' });
};

/**
 * PASSWORD
 */
exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) return next(new AppError('Invalid email address', 404));

  // 2) Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // 3) Send email to user with token
  try {
    const resetURL = `${process.env.WEBSITE_DOMAIN}reset-password/${resetToken}`;
    if (req.forgotPassword) await new Email(user, resetURL).sendPasswordReset();
    else await new Email(user, resetURL).sendPasswordResetRequest();
    res.status(200).json({
      status: 'success',
      message: `Email with instructions sent to ${user.email}. Check spam folder.`,
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    storeError('email', error).catch(() => {});
    return next(
      new AppError(
        'There was an error sending the email. Try again later!',
        500
      )
    );
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  }).select('+passwordResetToken +passwordResetExpires -pin -pinConfirm');

  // 2) If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired.', 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;

  // remove all Ip from whitelist except ip from request
  user.loggedDevices = [
    {
      deviceId: getDeviceId(req.useragent),
      ip: req.ipInfo.ip,
      location: `${req.ipInfo.city}, ${req.ipInfo.country}`,
      os: req.useragent.os,
      platform: req.useragent.platform,
      browser: req.useragent.browser,
      lastActivity: new Date(Date.now()),
    },
  ];
  await user.save();

  // 3) Inform user that his password has been reset
  res.status(200).json({
    status: 'success',
    message: 'Your password has been reset successfully.',
  });
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  const { passwordCurrent, password, passwordConfirm } = req.body;
  if (!passwordCurrent || !password || !passwordConfirm)
    return next(
      new AppError(
        'Please provide old password, new password and confirm password.',
        400
      )
    );
  // 1) Get user from collection
  const user = await User.findById(req.user.id).select(
    '+password -pin -pinConfirm'
  );

  // 2) Check if POSTed current password is correct
  if (!(await user.isCorrectPassword(passwordCurrent, user.password))) {
    return next(new AppError('Your current password is wrong.', 400));
  }

  if (passwordCurrent === password)
    return next(new AppError('New password cannot be the same as old.', 400));

  // 3) If so, update password
  user.password = password;
  user.passwordConfirm = passwordConfirm;
  await user.save();

  // 4) Log user in, send JWT
  sendResponseWithToken(user, req, res, 200);
});

exports.checkPassword = catchAsync(async (req, res, next) => {
  const { password } = req.body;
  if (!password)
    return next(
      new AppError(
        'Password required, please provide password and try again.',
        400
      )
    );
  const user = await User.findById(req.user._id).select('+password');
  const correctPassword = await user.isCorrectPassword(password, user.password);
  if (!correctPassword) return next(new AppError('Incorrect Password.', 400));
  next();
});

/**
 * PIN
 */
const handleWrongPin = async (user) => {
  if (
    user.pinLastWrongDate &&
    user.pinLastWrongDate.getTime() > Date.now() - 1000 * 60 * 60
  ) {
    user = await User.findByIdAndUpdate(
      user._id,
      {
        $inc: { pinTries: -1 },
        pinLastWrongDate: Date.now(),
      },
      { new: true }
    ).select('+pinTries');
    return user.pinTries;
  }
  user = await User.findByIdAndUpdate(
    user._id,
    {
      pinTries: 3,
      pinLastWrongDate: Date.now(),
    },
    { new: true }
  ).select('+pinTries');
  return user.pinTries;
};

exports.checkPin = catchAsync(async (req, res, next) => {
  const { pin } = req.body;
  if (!pin) return next(new AppError('Pin required for this action.', 400));
  const user = await User.findById(req.user._id).select(
    '+pin +pinActive +pinLastWrongDate +pinTries'
  );
  if (!user.pinActive)
    return next(
      new AppError('Pin has been blocked, please reset your pin.', 401)
    );
  const correctPin = await user.isCorrectPin(pin, user.pin);
  if (!correctPin) {
    const retries = await handleWrongPin(user);
    if (retries === 0) {
      await User.findByIdAndUpdate(
        user._id,
        {
          pinActive: false,
          pin: undefined,
        },
        { runValidators: false }
      );
      return next(
        new AppError('Pin has been blocked, please reset your pin.', 401)
      );
    }
    return next(
      new AppError(`Wrong pin. You have ${retries} retries left!`, 400)
    );
  }
  next();
});

exports.resetPin = catchAsync(async (req, res, next) => {
  const { pin, pinConfirm } = req.body;
  const user = await User.findById(req.user._id).select(
    '-password -passwordConfirm'
  );
  user.pin = pin;
  user.pinConfirm = pinConfirm;
  await user.save();
  res.status(200).json({
    status: 'success',
    message: 'Your pin has been reset successfully.',
  });
});
