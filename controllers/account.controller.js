const User = require('../models/User');
const AppError = require('../utils/AppError');
const catchAsync = require('../utils/catchAsync');
const { encrypt, decrypt } = require('../utils/encryption');

exports.getAccounts = catchAsync(async (req, res, next) => {
  res.status(200).json({
    status: 'success',
    accounts: req.user.accounts,
  });
});

// image in form of URL
exports.addAccount = catchAsync(async (req, res, next) => {
  const { name, userEmail, password, image } = req.body;
  if (!name || !password)
    return next(new AppError('Account name and password are required', 400));
  const encryptedData = encrypt(password);
  const user = await User.findOneAndUpdate(
    {
      _id: req.user.id,
      'accounts.name': { $ne: name },
    },
    {
      $push: {
        accounts: {
          name,
          userEmail,
          password: encryptedData.password,
          iv: encryptedData.iv,
          image,
          modified: Date.now(),
        },
      },
    },
    {
      new: true,
      runValidators: true,
    }
  );
  if (!user)
    return next(new AppError('Account already exists, try another name', 400));
  res.status(201).json({
    status: 'success',
    accounts: user.accounts,
  });
});

exports.getAccountPassword = catchAsync(async (req, res, next) => {
  const { accountId } = req.params;
  const user = await User.findOne({
    _id: req.user.id,
    'accounts._id': accountId,
  }).select('+accounts.password +accounts.iv');
  if (!user) return next(new AppError('Account not found', 404));
  const account = user.accounts.find(
    (value) => String(value._id) === String(accountId)
  );
  account.password = decrypt({ password: account.password, iv: account.iv });
  account.iv = undefined;
  user
    .updateOne({
      lastCheckedAccount: account.name,
      lastCheckedAccountDate: Date.now(),
    })
    .catch(() => {});
  res.status(200).json({
    status: 'success',
    account,
  });
});

exports.updateAccount = catchAsync(async (req, res, next) => {
  const { accountId } = req.params;
  const { name, userEmail, password, image } = req.body;
  if (!name && !userEmail && !password && !image)
    return next(
      new AppError('Please add to request body what you want to update', 400)
    );
  let $set = { 'accounts.$.modified': Date.now() + 1000 };
  if (userEmail || userEmail === '')
    $set = { ...$set, 'accounts.$.userEmail': userEmail };
  if (name) $set = { ...$set, 'accounts.$.name': name };
  if (password) {
    const encryptedData = encrypt(password);
    $set = {
      ...$set,
      'accounts.$.password': encryptedData.password,
      'accounts.$.iv': encryptedData.iv,
    };
  }
  if (image) $set = { ...$set, 'accounts.$.image': image };
  const updateOperator = { $set };
  const user = await User.findOneAndUpdate(
    {
      _id: req.user.id,
      'accounts._id': accountId,
      'accounts.name': { $ne: name },
    },
    updateOperator,
    {
      omitUndefined: true,
      new: true,
      runValidators: true,
    }
  );
  // CHECK IF ACCOUNT NAME ALREADY EXISTS OR USER/ACCOUN NOT FOUND
  if (!user) {
    const testUser = await User.findOne({
      _id: req.user.id,
      'accounts._id': accountId,
    });
    if (!testUser) return next(new AppError('User or Account not found', 404));
    return next(
      new AppError('Account name already exists, choose another name', 400)
    );
  }

  res.status(200).json({
    status: 'success',
    accounts: user.accounts,
  });
});

exports.deleteAccount = catchAsync(async (req, res, next) => {
  const { accountId } = req.params;
  const user = await User.findOneAndUpdate(
    {
      _id: req.user.id,
      'accounts._id': accountId,
    },
    {
      $pull: { accounts: { _id: accountId } },
    },
    {
      new: true,
    }
  );
  if (!user) return next(new AppError('User or Account not found', 404));
  res.status(204).json({
    status: 'success',
  });
});

exports.handleImageName = (req, res, next) => {
  const { image } = req.body;
  if (!image) return next();
  const index = image.lastIndexOf('/');
  if (index === -1) return next();
  const imageName = image.substring(index + 1);
  req.body.image = imageName;
  next();
};
