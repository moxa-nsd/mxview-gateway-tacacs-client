const net = require('net');
const crypto = require('crypto');
const tacacs = require('tacacs-plus');

class Tacacs {
    authenticate(host, port, username, password, sharedKey, authType) {
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
            client.on('error', function (err) {
                console.log(err);
                reject(err);
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
