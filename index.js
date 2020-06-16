const WebServer = require('./src/webServer');
const Tacacs = require('./src/tacacs');

const server = new WebServer(new Tacacs());
server.start();