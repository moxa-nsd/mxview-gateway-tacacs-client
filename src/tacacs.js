const net = require('net');
const crypto = require('crypto');
const tacacs = require('tacacs-plus');

class Tacacs {
    authenticate(host, port, username, password, sharedKey, authType, timeout) {
        // SIMPLE CLIENT
        return new Promise((resolve, reject)=>{
            const client = net.connect({ port: port, host: host }, function () {
                console.log('Client connected!');
    
                // now that we've connected, send the first auth packet
    
                const sessionIdBytes = crypto.randomBytes(4);
                const sessionId = Math.abs(sessionIdBytes.readInt32BE(0));
    
                console.log('Client: Session Id: ' + sessionId);
    
                // create the auth start body
                const authStart = tacacs.createAuthStart({
                    action: tacacs.TAC_PLUS_AUTHEN_LOGIN,
                    privLvl: tacacs.TAC_PLUS_PRIV_LVL_USER,
                    authenType: authType,
                    authenService: tacacs.TAC_PLUS_AUTHEN_SVC_LOGIN,
                    user: username,
                    port: port,
                    remAddr: '127.0.0.1',
                    data: null
                });
    
                const version = tacacs.createVersion(tacacs.TAC_PLUS_MAJOR_VER, tacacs.TAC_PLUS_MINOR_VER_DEFAULT);
                const sequenceNumber = 1;
                const encryptedAuthStart = tacacs.encodeByteData(sessionId, sharedKey, version, sequenceNumber, authStart);
    
                // create the tacacs+ header
                const headerOptions = {
                    majorVersion: tacacs.TAC_PLUS_MAJOR_VER,
                    minorVersion: tacacs.TAC_PLUS_MINOR_VER_DEFAULT,
                    type: tacacs.TAC_PLUS_AUTHEN,
                    sequenceNumber: sequenceNumber,
                    flags: tacacs.TAC_PLUS_SINGLE_CONNECT_FLAG, // setting this to zero assumes encryption is being used --  | tacacs.TAC_PLUS_UNENCRYPTED_FLAG
                    sessionId: sessionId,
                    length: authStart.length
                }
                const header = tacacs.createHeader(headerOptions);
    
                const packetToSend = Buffer.concat([header, encryptedAuthStart]);
    
                // send the auth start packet to the server
                console.log('Client: Sending: ' + packetToSend.length + ' bytes.');
                console.log('Client: ' + packetToSend.toString('hex'));
                client.write(packetToSend);
            });
            console.log(timeout);
            client.setTimeout(timeout || 3000);
            client.on('timeout', () => {
                console.log('socket timeout');
                client.end();
                reject('timeout');
            });
            client.on('error', function (err) {
                console.log(err);
                client.setTimeout(0);
                if(err.errno === 'ETIMEDOUT') {
                    // do nothing
                } else {
                    reject(err);
                }
            });
            client.on('close', function (had_err) {
                console.log('Client: Connection closed' + (had_err ? ' with errors.' : '') + '.');
            });
            client.on('data', function (data) {
                if (data) {
                    console.log('Client: Received Data: ' + data.toString('hex'));
                    // decode response
                    try {
                        console.log(sharedKey);
                        console.log(data);
                        const resp = tacacs.decodePacket({ packet: data, key: sharedKey });
                        if (resp) {
                            console.log('Client: Received Session Id: ' + resp.header.sessionId);
                            //console.log('Client: Decoded Response: ' + JSON.stringify(resp, null, 2));
        
                            if (resp.data.status === tacacs.TAC_PLUS_AUTHEN_STATUS_ERROR) {
                                console.log('Client: Authentication error!');
                                client.end();
                                reject('Client: Authentication error!');
                            }
                            else if (resp.data.status === tacacs.TAC_PLUS_AUTHEN_STATUS_FAIL) {
                                console.log('Client: *** Authentication Failed! ***');
                                client.end();
                                reject('Client: *** Authentication Failed! ***');
                            }
                            else if (resp.data.status === tacacs.TAC_PLUS_AUTHEN_STATUS_GETUSER
                                || resp.data.status === tacacs.TAC_PLUS_AUTHEN_STATUS_GETPASS) {
                                const newSeq = resp.header.sequenceNumber + 1;
                                
                                let msg = username;
                                if(resp.data.status === tacacs.TAC_PLUS_AUTHEN_STATUS_GETPASS) {
                                    msg = password;
                                }
                                const tRespOptions = {
                                    flags: 0x00,
                                    userMessage: msg,
                                    data: null
                                };
                                const tContinue = tacacs.createAuthContinue(tRespOptions);
                                const encryptedContinue = tacacs.encodeByteData(resp.header.sessionId, sharedKey, resp.header.versionByte, newSeq, tContinue);
        
                                const tRespHeader = {
                                    majorVersion: tacacs.TAC_PLUS_MAJOR_VER,
                                    minorVersion: tacacs.TAC_PLUS_MINOR_VER_DEFAULT,
                                    type: tacacs.TAC_PLUS_AUTHEN,
                                    sequenceNumber: newSeq,
                                    flags: resp.header.flags,
                                    sessionId: resp.header.sessionId,
                                    length: encryptedContinue.length
                                }
                                const header = tacacs.createHeader(tRespHeader);
        
                                const packetToSend = Buffer.concat([header, encryptedContinue]);
                                client.write(packetToSend);
                            }
                            else if (resp.data.status === tacacs.TAC_PLUS_AUTHEN_STATUS_PASS) {
                                console.log('Client: *** User Authenticated ***');
                                console.log('Client: ' + JSON.stringify(resp.data, null, 2));
                                client.end();
                                client.setTimeout(0);
                                resolve();
                            }
                            else {
                                console.log('Client: Some other status (' + resp.data.status + ')!');
                                const tRespOptions = {
                                    flags: tacacs.TAC_PLUS_CONTINUE_FLAG_ABORT,
                                    userMessage: null,
                                    data: null
                                };
                                const newSeq = resp.header.sequenceNumber + 1;
                                const tContinue = tacacs.createAuthContinue(tRespOptions);
                                const encryptedContinue = tacacs.encodeByteData(resp.header.sessionId, sharedKey, resp.header.versionByte, newSeq, tContinue);
        
                                const tRespHeader = {
                                    majorVersion: tacacs.TAC_PLUS_MAJOR_VER,
                                    minorVersion: tacacs.TAC_PLUS_MINOR_VER_DEFAULT,
                                    type: tacacs.TAC_PLUS_AUTHEN,
                                    sequenceNumber: newSeq,
                                    flags: resp.header.flags,
                                    sessionId: resp.header.sessionId,
                                    length: encryptedContinue.length
                                };
                                const header = tacacs.createHeader(tRespHeader);
        
                                const packetToSend = Buffer.concat([header, encryptedContinue]);
                                client.write(packetToSend);
                                client.end();
                            }
                        }
                    } catch(err) {
                        console.error(err);
                        client.setTimeout(0);
                        reject(err);
                    }
                }
                else {
                    console.log('Client: No data!');
                }
            });
        });
    }

    authorize(host, port, username, password, sharedKey, authType, timeout) {
        const sessionIdBytes = crypto.randomBytes(4);
        const sessionId = Math.abs(sessionIdBytes.readInt32BE(0));
        return new Promise((resolve, reject)=>{
            const client = net.connect({ port: port, host: host }, function () {
                const authorReq = tacacs.createAuthorizationRequest({
                    authenMethod: tacacs.TAC_PLUS_AUTHEN_METH_TACACSPLUS,
                    privLvl: tacacs.TAC_PLUS_PRIV_LVL_MAX,
                    authenType: authType,
                    authenService: tacacs.TAC_PLUS_AUTHEN_SVC_NONE,
                    user: username,
                    port: port,
                    remAddr: host,
                    args: ['service=shell']
                });
                console.log('Author Request: ' + authorReq.toString('hex'));
                const version = tacacs.createVersion(tacacs.TAC_PLUS_MAJOR_VER, tacacs.TAC_PLUS_MINOR_VER_DEFAULT);
                const sequenceNumber = 1;
                const encryptedAuth = tacacs.encodeByteData(sessionId, sharedKey, version, sequenceNumber, authorReq);
    
                // create the tacacs+ header
                const headerOptions = {
                    majorVersion: tacacs.TAC_PLUS_MAJOR_VER,
                    minorVersion: tacacs.TAC_PLUS_MINOR_VER_DEFAULT,
                    type: tacacs.TAC_PLUS_AUTHOR,
                    sequenceNumber: sequenceNumber,
                    flags: tacacs.TAC_PLUS_SINGLE_CONNECT_FLAG, // setting this to zero assumes encryption is being used --  | tacacs.TAC_PLUS_UNENCRYPTED_FLAG
                    sessionId: sessionId,
                    length: authorReq.length
                }
                const header = tacacs.createHeader(headerOptions);
    
                const packetToSend = Buffer.concat([header, encryptedAuth]);
    
                // send the auth start packet to the server
                console.log('Client: Sending: ' + packetToSend.length + ' bytes.');
                console.log('Client: ' + packetToSend.toString('hex'));
                client.write(packetToSend);
            });
            client.on('error', function (err) {
                console.log(err);
                if(err.errno === 'ETIMEDOUT') {
                    // do nothing
                } else {
                    reject(err);
                }
            });
            client.on('close', function (had_err) {
                console.log('Client: Connection closed' + (had_err ? ' with errors.' : '') + '.');
            });
            client.on('data', function (data) {
                if (data) {
                    console.log('Client: Received Data: ' + data.toString('hex'));
                    // decode response
                    try {
                        const resp = tacacs.decodePacket({ packet: data, key: sharedKey });
                        console.log(resp.rawData);
                        if (resp) {                         
                            console.log('Author Response: ' + resp.rawData.toString('hex'));
                            
                            const decodedResp = tacacs.decodeAuthorizationResponse(resp.rawData);
                            
                            console.log('Author Response: ' + JSON.stringify(decodedResp));
                            if(decodedResp.status === tacacs.TAC_PLUS_AUTHOR_STATUS_PASS_ADD) {
                                let level = 0;
                                decodedResp.args.forEach((arg)=>{
                                    if(arg.startsWith('priv-lvl')) {
                                        const tokens = arg.split('=');
                                        console.log(tokens);
                                        level = parseInt(tokens[1]);
                                    }
                                });
                                resolve({result: true, level: level});
                            }
                        }
                    } catch(err) {
                        console.error(err);
                        reject(err);
                    }
                }
                else {
                    console.log('Client: No data!');
                }
            });
        });
    }
}

module.exports = Tacacs;
