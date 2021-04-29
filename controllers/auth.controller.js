const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const catchAsync = require('../utils/catchAsync');
const Email = require('../utils/Email');
const AppError = require('../utils/AppError');
const storeError = require('../utils/storeError');

const signToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_DURATION,
  });

const sendResponseWithToken = (user, req, res, statusCode) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      // 1 hour
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
    // secure: process.env.NODE_ENV === 'production',
  };
  res.cookie('jwt', token, cookieOptions);

  // setting to undefined sensitive data
  user.password = undefined;
  user.status = undefined;
  user.passwordCurrent = undefined;

  // sending response
  res.status(statusCode).json({
    status: 'success',
    token,
    tokenExpires: cookieOptions.expires,
    user,
  });
};

exports.restrictTo = (roles) => (req, res, next) => {
  if (roles.includes(req.user.role)) return next();
  next(new AppError('You are unauthorized to access this route.', 403));
};

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

exports.signup = catchAsync(async (req, res, next) => {
  const { name, password, passwordConfirm, email } = req.body;
  const user = new User({ name, password, passwordConfirm, email });
  const emailToken = user.getEmailConfirmToken();
  await user.save();
  user.password = undefined;
  const url = `${process.env.WEBSITE_EMAIL_CONFIRM}${emailToken}`;
  try {
    await new Email(user, url).sendConfirmation();
  } catch (error) {
    await User.findByIdAndDelete(user.id);
    storeError('email', error).catch(() => {});
    return next(error);
  }
  res.status(201).json({
    status: 'success',
    message: `We sent an email to ${email} to make sure you own it. Please check your inbox and spam folder.`,
  });
});

exports.verifyEmail = catchAsync(async (req, res, next) => {
  const { emailToken } = req.params;
  const confirmationToken = crypto
    .createHash('sha256')
    .update(emailToken)
    .digest('hex');
  const user = await User.findOneAndUpdate(
    {
      confirmationToken,
      confirmationTokenExpires: { $gt: Date.now() },
    },
    {
      $unset: {
        confirmationToken: undefined,
        confirmationTokenExpires: undefined,
        nextReSendPosible: undefined,
        reSendCount: undefined,
      },
      status: 'Active',
    },
    { new: true, runValidators: true, context: 'query' }
  );
  if (!user) return next(new AppError('User verified or invalid token.', 400));
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
  const url = `${process.env.WEBSITE_EMAIL_CONFIRM}${emailToken}`;
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

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password)
    return next(new AppError('Please provide email and password', 400));
  const user = await User.findOne({ email }).select('+password +status');
  if (!user) return next(new AppError('Incorrect email or password.', 400));
  const correctPassword = await user.isCorrectPassword(password, user.password);
  if (!correctPassword)
    return next(new AppError('Incorrect email or password.', 400));
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
      try {
        const url = `${process.env.WEBSITE_DOMAIN}`;
        await new Email(user, url).sendWelcomeBack();
      } catch (error) {
        storeError('email', error).catch(() => {});
      }
      const updatedUser = await User.findByIdAndUpdate(
        user.id,
        {
          status: 'Active',
        },
        {
          new: true,
        }
      );
      sendResponseWithToken(updatedUser, req, res, 200);
      break;
    }
    case 'Active': {
      sendResponseWithToken(user, req, res, 200);
      break;
    }
    default: {
      return next(
        new AppError('Problem with database, please contact admin.', 500)
      );
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

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) return next(new AppError('Invalid email address', 404));
  // 1) Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });
  // 2) Send email to user with token
  try {
    const resetURL = `${process.env.WEBSITE_PASSWORD_RESET}${resetToken}`;
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
  }).select('+passwordResetToken +passwordResetExpires');

  // 2) If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired.', 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();
  // 3) Update changedPasswordAt property for the user
  // 4) Inform user that his password has been reset
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
  const user = await User.findById(req.user.id).select('+password');

  // 2) Check if POSTed current password is correct
  if (!(await user.isCorrectPassword(passwordCurrent, user.password))) {
    return next(new AppError('Your current password is wrong.', 400));
  }

  // 3) If so, update password
  user.passwordCurrent = passwordCurrent;
  user.password = password;
  user.passwordConfirm = passwordConfirm;
  await user.save();

  // 4) Log user in, send JWT
  sendResponseWithToken(user, req, res, 200);
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
  if (!user) return next(new AppError('User not found', 404));
  res.status(204).json({
    status: 'success',
  });
});

exports.checkPassword = catchAsync(async (req, res, next) => {
  const { password } = req.body;
  const user = await User.findById(req.user._id).select('+password');
  const correctPassword = await user.isCorrectPassword(password, user.password);
  if (!correctPassword) return next(new AppError('Incorrect Password.', 400));
  next();
});
