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

const unknownServerFail = (res) => {
    return res.status(500).json({ error: 'Oops.' });
};

const vaultCertLookup = (response, res, cn, action) => {
    if(response.errors)
        return res.status(400).json({ error: 'No cert found.' });
    else
        action(response,res,cn);
};

const vaultSolveChallenge = (response,res,cn) => {
    if(!response.data.challengeSolved) { // Deal with unsolved challenge
        const xhr = new XMLHttpRequest();
        xhr.open('put', `${vault_addr}${vaultSecretsEndpoint}/${cnPathEncode(cn)}`, true);
        vaultRequest(xhr, serialmapToken, () => { return res.json({ response: 'Success.' }); }, () => { return unknownServerFail(res) }, JSON.stringify({challengeSolved: true}));
    }
    else {
        return res.json({ response: 'Challenge already solved.' });
    }
};

const vaultGetCert = (response,res,cn) => {
    if(!response.data.challengeSolved) { return res.status(400).json({ error: 'Cert not approved.' }); }
    if(!response.data.serial) { return res.status(400).json({ error: 'No cert found.' }); }
    const serial = response.data.serial;
    const xhr = new XMLHttpRequest();
    const sendCert = () => {
        const response = JSON.parse(xhr.responseText);
        if(response.errors || !response.data.certificate) { return unknownServerFail(res); }
        return res.json({ response: 'Success.', cert: response.data.certificate });
    };
    xhr.open('get', `${vault_addr}${vaultPkiEndpoint}/cert/${serial}`, true);
    vaultRequest(xhr, pkiPublicToken, sendCert, () => { return unknownServerFail(res) });
};

const vaultGenCert = (response,res,cn) => {
    if(!response.data.challengeSolved) { return res.status(400).json({ error: 'Cert not approved.' }); }
    if(response.data.serial) { return res.status(400).json({ error: 'Cert already exists.' }); }
    const serial = response.data.serial;

};

const vaultSignCert = (response,res,cn) => {
    if(!response.data.challengeSolved) { return res.status(400).json({ error: 'Cert not approved.' }); }
    if(response.data.serial) { return res.status(400).json({ error: 'Cert already exists.' }); }
    const serial = response.data.serial;

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

app.use(bodyParser.json());

app.get(endpoint + '/get-ca',(req,res)=>{
    return res.json({'cert':ca});
});

app.post(endpoint + '/getcert', [check('email').isEmail(),check('code').isBase64()], (req,res)=>{
    const errors = validationResult(req);
    if (!errors.isEmpty())
        return res.status(400).json({ error: 'Invalid email or code.' });

    const email = req.body.email;
    const code  = req.body.code;

    const cnHash = crypto.createHash('sha384');
    const secret = Buffer.from(code, 'base64');
    cnHash.update(email);
    cnHash.update(secret);
    const cn = cnHash.digest('base64').substr(0,64);
    const xhrVault = new XMLHttpRequest();
    xhrVault.open('get',`${vault_addr}${vaultSecretsEndpoint}/${cnPathEncode(cn)}`, true);
    vaultRequest(xhrVault, serialmapToken, () => { return vaultCertLookup(JSON.parse(xhrVault.responseText),res,cn,vaultGetCert); }, () => { return unknownServerFail(res) });
});

// app.post(endpoint + '/signcsr',(req,res)=>{
//
// });

// app.post(endpoint + '/genp12',(req,res)=>{
//     forge.pki.certificateFromPem(pem);
//     forge.pki.privateKeyFromPem(pem);
//     forge.pkcs12.toPkcs12Asn1(privateKey, certificateChain, 'password');
// });

app.post(endpoint + '/solvechallenge', [check('email').isEmail(),check('code').isBase64()], (req,res)=>{
    const errors = validationResult(req);
    if (!errors.isEmpty())
        return res.status(400).json({ error: 'Invalid email or code.' });

    const email = req.body.email;
    const code  = req.body.code;

    const cnHash = crypto.createHash('sha384');
    const secret = Buffer.from(code, 'base64');
    cnHash.update(email);
    cnHash.update(secret);
    const cn = cnHash.digest('base64').substr(0,64);

    const xhrVault = new XMLHttpRequest();
    xhrVault.open('get',`${vault_addr}${vaultSecretsEndpoint}/${cnPathEncode(cn)}`, true);
    vaultRequest(xhrVault, serialmapToken, () => { return vaultCertLookup(JSON.parse(xhrVault.responseText),res,cn,vaultSolveChallenge); }, () => { return unknownServerFail(res) });
});

app.post(endpoint + '/signup', [check('email').isEmail()],(req,res)=>{
    const errors = validationResult(req);
    if (!errors.isEmpty())
        return res.status(400).json({ error: 'Invalid email.' });

    const xhr = new XMLHttpRequest();
    xhr.open('post','https://www.google.com/recaptcha/api/siteverify', true);

    if(!req.body.captcha)
        return res.status(400).json({ error: 'Missing captcha token.' });

    const success = () => {
        const email = req.body.email;
        const captchaVerification = JSON.parse(xhr.responseText);
        if(!captchaVerification.success || !hostnameWhitelist.includes(captchaVerification.hostname))
            return res.status(400).json({ error: 'Invalid captcha response.' });

        const cnHash = crypto.createHash('sha384');
        const secret = crypto.randomBytes(384/8);
        cnHash.update(email);
        cnHash.update(secret);
        const cn = cnHash.digest('base64').substr(0,64);

        const xhrVault = new XMLHttpRequest();
        xhrVault.open('post',`${vault_addr}${vaultSecretsEndpoint}/${cnPathEncode(cn)}`, true);
        vaultRequest(xhrVault, serialmapToken, () => {}, () => { return unknownServerFail(res) }, JSON.stringify({challengeSolved:false}));

        sendRegistrationConfirmation(email, secret.toString('base64'));

        return res.json({ response: 'Success.' });
    };

    const fail = () => {
        return res.status(500).json({ error: 'Captcha processing error.' });
    };

    request(xhr, success, fail, 'application/x-www-form-urlencoded', `secret=${captchaSecret}&response=${req.body.captcha}&remoteip=${req.connection.remoteAddress}`);
});

// 404
app.use(function(req, res, next) {
    return res.status(404).json({ error: 'Route '+req.url+' Not found.' });
});

// 500 - Any server error
app.use(function(err, req, res, next) {
    return res.status(500).json({ error: 'Server error.' });
});

app.listen(process.env.NODE_PORT || 3000);