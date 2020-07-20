const fse = require('fs-extra');

if(typeof process.env.MXVIEW_GATEWAY_PATH_DEV === 'undefined')
{
    console.error('You have to set MXVIEW_GATEWAY_PATH_DEV first before you use this script.');
    process.exit();
}

const gatewayPath = process.env.MXVIEW_GATEWAY_PATH_DEV;
const tacacsPath = gatewayPath + '/tacacs';
fse.ensureDirSync(tacacsPath);
fse.copySync('./index.js', tacacsPath + '/index.js');
fse.copySync('./src/', tacacsPath + '/src/');
fse.copySync('./node_modules/', tacacsPath + '/node_modules/');

console.log('Tacacs service is copied');