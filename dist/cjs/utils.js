"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.concatenateBuffers = exports.bufferToHex = exports.sha256 = exports.parseBase64url = exports.toBase64url = exports.isBase64url = exports.parseBuffer = exports.toBuffer = exports.randomChallenge = void 0;
/********************************
     Encoding/Decoding Utils
********************************/
const cryptolib = __importStar(require("crypto"));
const crypto = cryptolib.webcrypto;
/*
let webCrypto :any = null

export async function getCrypto() {
    if(!webCrypto) {
        console.log(window?.crypto)
        webCrypto = window?.crypto ?? (await import("crypto")).webcrypto
        console.log(webCrypto)
    }
    return webCrypto
}
*/
function randomChallenge() {
    return crypto.randomUUID();
}
exports.randomChallenge = randomChallenge;
function toBuffer(txt) {
    return Uint8Array.from(txt, c => c.charCodeAt(0)).buffer;
}
exports.toBuffer = toBuffer;
function parseBuffer(buffer) {
    return String.fromCharCode(...new Uint8Array(buffer));
}
exports.parseBuffer = parseBuffer;
function isBase64url(txt) {
    return txt.match(/^[a-zA-Z0-9\-_]+=*$/) !== null;
}
exports.isBase64url = isBase64url;
function toBase64url(buffer) {
    const txt = btoa(parseBuffer(buffer)); // base64
    return txt.replaceAll('+', '-').replaceAll('/', '_');
}
exports.toBase64url = toBase64url;
function parseBase64url(txt) {
    txt = txt.replaceAll('-', '+').replaceAll('_', '/'); // base64url -> base64
    return toBuffer(atob(txt));
}
exports.parseBase64url = parseBase64url;
async function sha256(buffer) {
    return await crypto.subtle.digest('SHA-256', buffer);
}
exports.sha256 = sha256;
function bufferToHex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}
exports.bufferToHex = bufferToHex;
function concatenateBuffers(buffer1, buffer2) {
    var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp;
}
exports.concatenateBuffers = concatenateBuffers;
;
