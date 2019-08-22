'use strict';
const path = require('path');
const url = require('url');
const crypto = require('crypto');
const tokenPath = '/tokens';
const tokenSuffix = 'token';
const vault_addr = 'http://127.0.0.1:8200';
const version = 'v1';
const vaultPkiEndpoint = '/v1/pki';
const vaultSecretsEndpoint = '/v1/serial';
const endpoint = '/api/' + version;
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const forge = require('node-forge');
const fs = require('fs');
const pkiPublicToken = fs.readFileSync(`${tokenPath}/public.${tokenSuffix}`, 'utf8');
const pkiClientToken = fs.readFileSync(`${tokenPath}/client.${tokenSuffix}`, 'utf8');
const pkiServerToken = fs.readFileSync(`${tokenPath}/server.${tokenSuffix}`, 'utf8');
const serialmapToken = fs.readFileSync(`${tokenPath}/serial-map.${tokenSuffix}`, 'utf8');
const captchaSecret = fs.readFileSync(`${tokenPath}/captcha.${tokenSuffix}`, 'utf8');
const ca = fs.readFileSync(`/etc/openvpn/public/ca.crt`, 'utf8');
const { check, validationResult } = require('express-validator');
const XMLHttpRequest = require('xmlhttprequest').XMLHttpRequest;
const hostnameWhitelist = ['vpn.sohamroy.me'];
const nodemailer = require('nodemailer');

const certConfigGeneral = {
    ttl: '24h'
};

const unknownServerFail = (res) => {
    return res.status(500).json({ error: 'Oops.' });
};

const vaultCertLookup = (response, res, input, action) => {
    if(response.errors)
        return res.status(404).json({ error: 'No cert found.' });
    else
        action(response,res,input);
};

const vaultSolveChallenge = (response,res,input) => {
    if(!response.data.challengeSolved) { // Deal with unsolved challenge
        const xhr = new XMLHttpRequest();
        xhr.open('put', `${vault_addr}${vaultSecretsEndpoint}/${cnPathEncode(input.cn)}`, true);
        vaultRequest(xhr, serialmapToken, () => { return res.json({ response: 'Success.' }); }, () => { return unknownServerFail(res) }, JSON.stringify({challengeSolved: true}));
    }
    else {
        return res.json({ response: 'Challenge already solved.' });
    }
};

const vaultGetCert = (response,res,input) => {
    if(!response.data.challengeSolved) { return res.status(402).json({ error: 'Cert not approved.' }); }
    if(!response.data.serial) { return res.status(404).json({ error: 'No cert found.' }); }
    const serial = response.data.serial;
    const xhr = new XMLHttpRequest();
    const sendCert = () => {
        const response = JSON.parse(xhr.responseText);
        if(response.errors) { return unknownServerFail(res); }
        return res.json({ response: 'Success.', cert: response.data.certificate });
    };
    xhr.open('get', `${vault_addr}${vaultPkiEndpoint}/cert/${serial}`, true);
    vaultRequest(xhr, pkiPublicToken, sendCert, () => { return unknownServerFail(res) });
};

const vaultGenCert = (response,res,input) => {
    if(!response.data.challengeSolved) { return res.status(402).json({ error: 'Cert not approved.' }); }
    if(response.data.serial) { return res.status(403).json({ error: 'Cert already exists.' }); }
    const certConfig = certConfigGeneral;
    certConfig.common_name = input.cn;
    const xhr = new XMLHttpRequest();
    const genCert = () => {
        const responseGenCert = JSON.parse(xhr.responseText);
        if(responseGenCert.errors) { return unknownServerFail(res); }

        const updatedSerial = response.data;
        updatedSerial.serial = responseGenCert.data.serial_number;

        const xhrVault = new XMLHttpRequest();
        xhrVault.open('post',`${vault_addr}${vaultSecretsEndpoint}/${cnPathEncode(input.cn)}`, true);
        vaultRequest(xhrVault, serialmapToken, () => {}, () => { return unknownServerFail(res) }, JSON.stringify(updatedSerial));

        const cert = forge.pki.certificateFromPem(responseGenCert.data.certificate);
        const ca = forge.pki.certificateFromPem(responseGenCert.data.issuing_ca);
        const key = forge.pki.privateKeyFromPem(responseGenCert.data.private_key);
        const pkcs12Asn1 = forge.pkcs12.toPkcs12Asn1(key, [ca,cert], input.code);
        const pkcs12Der = forge.asn1.toDer(pkcs12Asn1).getBytes();
        const pkcs12Buff = Buffer.from(pkcs12Der,'binary');
        const pkcs12Base64 = pkcs12Buff.toString('base64');

        sendPKCS12(input.email, pkcs12Buff);

        return res.json({ response: 'Success.', pkcs12: pkcs12Base64 });
    };
    xhr.open('post', `${vault_addr}${vaultPkiEndpoint}/issue/client`, true);
    vaultRequest(xhr, pkiClientToken, genCert, () => { return unknownServerFail(res) }, JSON.stringify(certConfig));
};

const vaultSignCert = (response,res,input) => {
    if(!response.data.challengeSolved) { return res.status(402).json({ error: 'Cert not approved.' }); }
    if(response.data.serial) { return res.status(403).json({ error: 'Cert already exists.' }); }


};

const cnPathEncode = (cn) => {
    return encodeURIComponent(cn).replace(/%/g,'-');
};

const transporter = nodemailer.createTransport({
    host: 'localhost',
    port: 25
});

const request = (xhr, success, error, contentType, data) => {
    xhr.onload = success;
    xhr.onerror = error;
    xhr.setRequestHeader('Content-Type', contentType);
    xhr.send(data);
};

const vaultRequest = (xhr, token, success, fail, data) => {
    xhr.setRequestHeader('X-Vault-Token', token);
    if(data)
        request(xhr, success, fail, 'application/json', data);
    else
        request(xhr, success, fail, 'application/json');
};

const sendRegistrationConfirmation = (address,code) => {
    transporter.sendMail({
        from: 'Soham Roy VPN Registration <registration@vpn.sohamroy.me>',
        to: address,
        subject: 'VPN Registration Confirmation',
        text: `Use the following secret code to access your certificate:\n\n${code}\n\n\nDo not reply to this email.`
    });
};

const sendPKCS12 = (address,pkcs12) => {
    transporter.sendMail({
        from: 'Soham Roy VPN CA <ca@vpn.sohamroy.me>',
        to: address,
        subject: 'VPN PKCS#12',
        text: `Attached is the PKCS#12 file to access the VPN service. The password is your code.\n\nDo not reply to this email.`,
        attachments: [{
            filename: 'client.p12',
            content: pkcs12,
            contentType: 'application/x-pkcs12'
        }]
    });
};

app.use(bodyParser.json());

app.get(endpoint + '/getca',(req,res) => {
    return res.json({'cert':ca});
});

app.post(endpoint + '/getcert', [check('email').isEmail(),check('code').isBase64()], (req,res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
        return res.status(422).json({ error: 'Invalid email or code.' });

    const email = req.body.email;
    const code  = req.body.code;

    const cnHash = crypto.createHash('sha384');
    const secret = Buffer.from(code, 'base64');
    cnHash.update(email);
    cnHash.update(secret);
    const cn = cnHash.digest('base64').substr(0,63);
    const xhrVault = new XMLHttpRequest();
    xhrVault.open('get',`${vault_addr}${vaultSecretsEndpoint}/${cnPathEncode(cn)}`, true);
    vaultRequest(xhrVault, serialmapToken, () => { return vaultCertLookup(JSON.parse(xhrVault.responseText),res,{cn:cn},vaultGetCert); }, () => { return unknownServerFail(res) });
});

// app.post(endpoint + '/signcsr',(req,res) => {
//
// });

app.post(endpoint + '/genp12', [check('email').isEmail(),check('code').isBase64()], (req,res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
        return res.status(422).json({ error: 'Invalid email or code.' });

    const email = req.body.email;
    const code  = req.body.code;

    const cnHash = crypto.createHash('sha384');
    const secret = Buffer.from(code, 'base64');
    cnHash.update(email);
    cnHash.update(secret);
    const cn = cnHash.digest('base64').substr(0,63);
    const xhrVault = new XMLHttpRequest();
    xhrVault.open('get',`${vault_addr}${vaultSecretsEndpoint}/${cnPathEncode(cn)}`, true);
    vaultRequest(xhrVault, serialmapToken, () => { return vaultCertLookup(JSON.parse(xhrVault.responseText),res,{cn:cn,code:code,email:email},vaultGenCert); }, () => { return unknownServerFail(res) });
});

app.post(endpoint + '/solvechallenge', [check('email').isEmail(),check('code').isBase64()], (req,res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
        return res.status(422).json({ error: 'Invalid email or code.' });

    const email = req.body.email;
    const code  = req.body.code;

    const cnHash = crypto.createHash('sha384');
    const secret = Buffer.from(code, 'base64');
    cnHash.update(email);
    cnHash.update(secret);
    const cn = cnHash.digest('base64').substr(0,63);

    const xhrVault = new XMLHttpRequest();
    xhrVault.open('get',`${vault_addr}${vaultSecretsEndpoint}/${cnPathEncode(cn)}`, true);
    vaultRequest(xhrVault, serialmapToken, () => { return vaultCertLookup(JSON.parse(xhrVault.responseText),res,{cn:cn},vaultSolveChallenge); }, () => { return unknownServerFail(res) });
});

app.post(endpoint + '/signup', [check('email').isEmail()],(req,res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
        return res.status(422).json({ error: 'Invalid email.' });

    const xhr = new XMLHttpRequest();
    xhr.open('post','https://www.google.com/recaptcha/api/siteverify', true);

    if(!req.body.captcha)
        return res.status(422).json({ error: 'Missing captcha token.' });

    const success = () => {
        const email = req.body.email;
        const captchaVerification = JSON.parse(xhr.responseText);
        if(!captchaVerification.success || !hostnameWhitelist.includes(captchaVerification.hostname))
            return res.status(403).json({ error: 'Invalid captcha response.' });

        const cnHash = crypto.createHash('sha384');
        const secret = crypto.randomBytes(384/8);
        cnHash.update(email);
        cnHash.update(secret);
        const cn = cnHash.digest('base64').substr(0,63);

        const xhrVault = new XMLHttpRequest();
        xhrVault.open('post',`${vault_addr}${vaultSecretsEndpoint}/${cnPathEncode(cn)}`, true);
        vaultRequest(xhrVault, serialmapToken, () => {}, () => { return unknownServerFail(res) }, JSON.stringify({challengeSolved:false}));

        sendRegistrationConfirmation(email, secret.toString('base64'));

        return res.json({ response: 'Success.' });
    };

    const fail = () => {
        return unknownServerFail(res);
    };

    request(xhr, success, fail, 'application/x-www-form-urlencoded', `secret=${captchaSecret}&response=${req.body.captcha}&remoteip=${req.connection.remoteAddress}`);
});

// 404
app.use(function(req, res) {
    return res.status(404).json({ error: 'Route '+req.url+' Not found.' });
});

app.listen(process.env.NODE_PORT || 3000);