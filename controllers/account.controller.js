const User = require('../models/User');
const IvKey = require('../models/IvKey');
const AppError = require('../utils/AppError');
const catchAsync = require('../utils/catchAsync');
const { encrypt, decrypt } = require('../utils/encryption');

exports.getAccounts = catchAsync(async (req, res, next) => {
  res.status(200).json({
    status: 'success',
    accounts: req.user.accounts,
  });
});

exports.addAccount = catchAsync(async (req, res, next) => {
  const { name, userEmail, password, image } = req.body;
  if (!name || !password)
    return next(new AppError('Account name and password are required', 400));
  const encryptedData = encrypt(password);

  // 1. open session and start transaction
  const session = await User.startSession();
  session.startTransaction();

  // 2. create ivkeys record and push new account to user.accounts
  try {
    // 2.a add new account
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
            image,
            modified: Date.now(),
          },
        },
      },
      {
        new: true,
        runValidators: true,
        session,
      }
    );
    if (!user)
      throw new AppError('Account already exists, try another name', 400);

    // GET ACCOUNT._ID OF THE NEW ACCOUNT
    const newAccount = user.accounts.sort((a, b) => a._id > b._id)[
      user.accounts.length - 1
    ];
    if (!newAccount || newAccount.name !== name)
      throw new AppError('Failed to add account, try again', 400);

    // 2.b add ivKey record
    await IvKey.create(
      [
        {
          accountId: newAccount._id,
          iv: encryptedData.iv,
        },
      ],
      { session }
    );

    // COMMIT UPDATES
    await session.commitTransaction();
    session.endSession();

    // SEND RESPONSE
    res.status(201).json({
      status: 'success',
      accounts: user.accounts,
    });
  } catch (error) {
    // REVERSE CHANGES
    await session.abortTransaction();
    session.endSession();
    return next(error);
  }
});

exports.getAccountPassword = catchAsync(async (req, res, next) => {
  const { accountId } = req.params;

  // 1. find user that containts account with provided accountId
  const user = await User.findOne({
    _id: req.user.id,
    'accounts._id': accountId,
  }).select('+accounts.password');
  if (!user) return next(new AppError('Account not found', 404));

  // 2. find iv key belonging to specific account
  const ivKey = await IvKey.findOne({ accountId });
  if (!ivKey) return next(new AppError('Account not found', 404));

  // 3. get specific account from user accounts array
  const account = user.accounts.find(
    (value) => String(value._id) === String(accountId)
  );
  account.password = decrypt({ password: account.password, iv: ivKey.iv });
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
  const session = await User.startSession();
  session.startTransaction();

  const { accountId } = req.params;
  const { name, userEmail, password, image } = req.body;
  if (!name && !userEmail && !password && !image)
    return next(
      new AppError('Please add to request body what you want to update', 400)
    );

  const userUpdateQuery = User.findOneAndUpdate(
    {
      _id: req.user.id,
      'accounts._id': accountId,
      'accounts.name': { $ne: name },
    },
    {
      'accounts.$.modified': Date.now(),
      'accounts.$.userEmail': userEmail || undefined,
      'accounts.$.name': name || undefined,
      'accounts.$.image': image || undefined,
    },
    {
      omitUndefined: true,
      new: true,
      runValidators: true,
      session,
    }
  );
  let ivKeyUpdateQuery;
  if (password) {
    const encryptedData = encrypt(password);
    userUpdateQuery.setUpdate({
      ...userUpdateQuery.getUpdate(),
      'accounts.$.password': encryptedData.password,
    });
    ivKeyUpdateQuery = IvKey.findOneAndUpdate(
      { accountId },
      { iv: encryptedData.iv },
      { session }
    );
  }
  try {
    const user = await userUpdateQuery;
    // CHECK IF ACCOUNT NAME ALREADY EXISTS OR USER/ACCOUNT NOT FOUND
    if (!user) {
      const testUser = await User.findOne({
        _id: req.user.id,
        'accounts._id': accountId,
      });
      if (!testUser) throw new AppError('Account not found', 404);
      throw new AppError(
        'Account name already exists, choose another name',
        400
      );
    }
    if (ivKeyUpdateQuery) {
      const ivKey = await ivKeyUpdateQuery;
      if (!ivKey) throw new AppError('Account Info not found', 404);
    }

    // COMMIT UPDATES
    await session.commitTransaction();
    session.endSession();

    // SEND RESPONSE
    res.status(200).json({
      status: 'success',
      accounts: user.accounts,
    });
  } catch (error) {
    // If an error occurred, abort the whole transaction and
    // undo any changes that might have happened
    await session.abortTransaction();
    session.endSession();
    return next(error);
  }
});

exports.deleteAccount = catchAsync(async (req, res, next) => {
  const { accountId } = req.params;

  // 1. open session and start transaction
  const session = await User.startSession();
  session.startTransaction();

  try {
    // 1. delete account from users database
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
        session,
      }
    );
    if (!user) throw new AppError('Account not found.', 404);

    // 2. delete ivKey record from ivkeys database
    const ivKey = await IvKey.findOneAndDelete({ accountId }, { session });
    if (!ivKey) return next(new AppError('Account not found.', 404));

    // COMMIT UPDATES
    await session.commitTransaction();
    session.endSession();

    res.status(204).json({
      status: 'success',
    });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    return next(error);
  }
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
