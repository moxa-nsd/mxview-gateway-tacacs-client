const express = require('express');
const bodyParser = require('body-parser');
const tacacsPlus = require('tacacs-plus');
const app = express();

class WebServer {
    constructor(tacacs) {
        // parse application/x-www-form-urlencoded
        app.use(bodyParser.urlencoded({ extended: false }))

        // parse application/json
        app.use(bodyParser.json())
        app.post('/api/login/tacacsPlus', (req, res)=>{
            console.log(req.body);
            const host = req.body.host;
            const port = req.body.port;
            const authType = req.body.auth_type;
            const username = req.body.username;
            const password = req.body.password;
            const sharedKey = req.body.shared_key;
            const timeout = parseInt(req.body.timeout);
            tacacs.authenticate(host, port, username, password, sharedKey, this._parseAuthType(authType), timeout).then((result)=>{
                return tacacs.authorize(host, port, username, password, sharedKey, this._parseAuthType(authType), timeout);
            }).then((result)=>{
                console.log(result);
                res.status(200).send({level: result.level});
            }).catch((err)=>{
                console.log(err);
                if(err === 'timeout') {
                    res.status(408).send(err);
                } else {
                    res.status(400).send(err);
                }
            });
        });
    }

    start() {     
        app.listen(4106, function () {
            console.log('Example app listening on port 4106!');
        });
    }

    _parseAuthType(authType) {
        switch(authType) {
            case 0: // ASCII:
                return tacacsPlus.TAC_PLUS_AUTHEN_TYPE_ASCII;
                break;
            case 1: // PAP
                return tacacsPlus.TAC_PLUS_AUTHEN_TYPE_PAP;
                break;
            case 2: // CHAP
                return tacacsPlus.TAC_PLUS_AUTHEN_TYPE_CHAP;
                break;
            case 3: // MSCHAP
                return tacacsPlus.TAC_PLUS_AUTHEN_TYPE_MSCHAP;
                break;
            default:
                return tacacsPlus.TAC_PLUS_AUTHEN_TYPE_ASCII;
        }
    }
}

module.exports = WebServer;
