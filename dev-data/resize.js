const path = require('path');
const fs = require('fs');

const images = fs.readdirSync(path.resolve(__dirname, '../public/img'));
images.forEach((image) => {
  fs.writeFile('./icons-list.txt', image, (err) => {
    if (err) return console.log(err);
    console.log('Hello World > helloworld.txt');
  });
});

// const usedNames = new Map();

// const newName = (name) => {
//   name = name.substring(4).replace(/'\s'/g, '-');
//   if (!usedNames.has(name)) {
//     usedNames.set(name, 0);
//     console.log(name);
//     return name;
//   }
//   const occurence = usedNames.get(name) + 1;
//   usedNames.set(name, occurence);
//   name = name.replace(/.png$/, `-${occurence}.png`);
//   console.log(name);
//   return name;
// };

// images.forEach((image) => {
//   sharp(path.resolve(__dirname, './icons', image))
//     .resize(64, 64)
//     .toFile(path.resolve(__dirname, './icons', newName(image)), (err) => {
//       console.log(err);
//       // output.jpg is a 300 pixels wide and 200 pixels high image
//       // containing a scaled and cropped version of input.jpg
//     });
// });

// images.forEach((image) => {
//   fs.rename(
//     path.resolve(__dirname, '../public/img', image),
//     path.resolve(__dirname, '../public/img', image.replace(/\s/, '-')),
//     () => {
//       console.log('\nFile Renamed!\n');
//     }
//   );
// });
