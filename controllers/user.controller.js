const User = require('../models/User');
const AppError = require('../utils/AppError');
const catchAsync = require('../utils/catchAsync');

/**
 * USER MIDDLEWARES
 */
const getAllowedFieldsUpdateUser = (() => {
  const allowed = ['name'];
  return (fields) => {
    const returnValue = {};
    Object.entries(fields).forEach(([key, value]) => {
      if (allowed.includes(key)) returnValue[key] = value;
    });
    return returnValue;
  };
})();

exports.getMe = (req, res, next) => {
  res.status(200).json({
    status: 'success',
    user: req.user,
  });
};

exports.updateMe = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(
    req.user.id,
    {
      $set: getAllowedFieldsUpdateUser(req.body),
    },
    {
      new: true,
      runValidators: true,
    }
  );
  if (!user) return next(new AppError('User not found.', 404));
  res.status(200).json({
    status: 'success',
    user,
  });
});

exports.deleteMe = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndDelete(req.user.id);
  if (!user) return next(new AppError('User not found', 404));
  res.status(200).json({
    status: 'success',
    message: 'User deleted forever. Signup if you want to use PassKeep again.',
  });
});

exports.deactivateMe = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(
    req.user.id,
    {
      status: 'Inactive',
    },
    {
      new: true,
      runValidators: true,
    }
  );
  if (!user) return next(new AppError('User not found', 404));
  res.status(200).json({
    status: 'success',
    message: 'User deactivated successfully. Login to activate again.',
  });
});

/**
 * ADMIN MIDDLEWARES
 */
const getAllowedFieldsUpdateAdmin = (() => {
  const allowed = [
    'name',
    'email',
    'status',
    'role',
    'reSendEmail',
    'accountCreated',
    'accounts',
    'lastCheckedAccount',
    'lastCheckedAccountDate',
  ];
  return (fields) => {
    const returnValue = {};
    Object.entries(fields).forEach(([key, value]) => {
      if (allowed.includes(key)) returnValue[key] = value;
    });
    return returnValue;
  };
})();

exports.getAllUsers = catchAsync(async (req, res, next) => {
  const users = await User.find();
  res.status(200).json({
    status: 'success',
    users,
  });
});

exports.getUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  res.status(200).json({
    status: 'success',
    user,
  });
});

exports.createUser = catchAsync(async (req, res, next) => {
  const user = await User.create(req.body);
  user.password = undefined;
  res.status(200).json({
    status: 'success',
    user,
  });
});

exports.updateUser = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(
    req.params.id,
    {
      $set: getAllowedFieldsUpdateAdmin(req.body),
    },
    {
      new: true,
      runValidators: true,
    }
  );
  if (!user) return next(new AppError('User not found.', 404));
  res.status(200).json({
    status: 'success',
    user,
  });
});

exports.deleteUser = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndDelete(req.params.id);
  if (!user) return next(new AppError('User not found.', 404));
  res.status(204).json({
    status: 'success',
  });
});
