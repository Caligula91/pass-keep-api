const path = require('path');
const fs = require('fs');

const allImagesSet = new Set(
  fs.readdirSync(path.resolve(__dirname, '../public/img'))
);

module.exports = {
  allImages: Array.from(allImagesSet),
  allImagesSet,
};
