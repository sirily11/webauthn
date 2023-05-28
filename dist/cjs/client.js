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
exports.authenticate = exports.register = exports.isLocalAuthenticator = exports.isAvailable = void 0;
const utils = __importStar(require("./utils.js"));
/**
 * Returns whether passwordless authentication is available on this browser/platform or not.
 */
function isAvailable() {
    return !!window.PublicKeyCredential;
}
exports.isAvailable = isAvailable;
/**
 * Returns whether the device itself can be used as authenticator.
 */
async function isLocalAuthenticator() {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
}
exports.isLocalAuthenticator = isLocalAuthenticator;
async function getAuthAttachment(authType) {
    if (authType === "local")
        return "platform";
    if (authType === "roaming" || authType === "extern")
        return "cross-platform";
    if (authType === "both")
        return undefined; // The webauthn protocol considers `null` as invalid but `undefined` as "both"!
    // the default case: "auto", depending on device capabilities
    try {
        if (await isLocalAuthenticator())
            return "platform";
        else
            return "cross-platform";
    }
    catch (e) {
        // might happen due to some security policies
        // see https://w3c.github.io/webauthn/#sctn-isUserVerifyingPlatformAuthenticatorAvailable
        return undefined; // The webauthn protocol considers `null` as invalid but `undefined` as "both"!
    }
}
function getAlgoName(num) {
    switch (num) {
        case -7: return "ES256";
        // case -8 ignored to to its rarity
        case -257: return "RS256";
        default: throw new Error(`Unknown algorithm code: ${num}`);
    }
}
/**
 * Creates a cryptographic key pair, in order to register the public key for later passwordless authentication.
 *
 * @param {string} username
 * @param {string} challenge A server-side randomly generated string.
 * @param {Object} [options] Optional parameters.
 * @param {number} [options.timeout=60000] Number of milliseconds the user has to respond to the biometric/PIN check.
 * @param {'required'|'preferred'|'discouraged'} [options.userVerification='required'] Whether to prompt for biometric/PIN check or not.
 * @param {'auto'|'local'|'roaming'|'both'}       [options.authenticatorType='auto'] Which device to use as authenticator.
 *          'auto': if the local device can be used as authenticator it will be preferred. Otherwise it will prompt for a roaming device.
 *          'local': use the local device (using TouchID, FaceID, Windows Hello or PIN)
 *          'roaming': use a roaming device (security key or connected phone)
 *          'both': prompt the user to choose between local or roaming device. The UI and user interaction in this case is platform specific.
 * @param {boolean} [attestation=false] If enabled, the device attestation and clientData will be provided as Base64url encoded binary data.
 *                                Note that this is not available on some platforms.
 */
async function register(username, challenge, options) {
    options = options ?? {};
    if (!utils.isBase64url(challenge))
        throw new Error('Provided challenge is not properly encoded in Base64url');
    const creationOptions = {
        challenge: utils.parseBase64url(challenge),
        rp: {
            id: window.location.hostname,
            name: window.location.hostname
        },
        user: {
            id: await utils.sha256(new TextEncoder().encode(username)),
            name: username,
            displayName: username,
        },
        pubKeyCredParams: [
            { alg: -7, type: "public-key" },
            { alg: -257, type: "public-key" }, // RS256 (for Windows Hello and others)
        ],
        timeout: options.timeout ?? 60000,
        authenticatorSelection: {
            userVerification: options.userVerification ?? "required",
            authenticatorAttachment: await getAuthAttachment(options.authenticatorType ?? "auto"),
        },
        attestation: "direct" // options.attestation ? "direct" : "none"
    };
    if (options.debug)
        console.debug(creationOptions);
    const credential = await navigator.credentials.create({ publicKey: creationOptions }); //PublicKeyCredential
    if (options.debug)
        console.debug(credential);
    const response = credential.response; // AuthenticatorAttestationResponse
    let registration = {
        username: username,
        credential: {
            id: credential.id,
            publicKey: utils.toBase64url(response.getPublicKey()),
            algorithm: getAlgoName(credential.response.getPublicKeyAlgorithm())
        },
        authenticatorData: utils.toBase64url(response.getAuthenticatorData()),
        clientData: utils.toBase64url(response.clientDataJSON),
    };
    if (options.attestation) {
        registration.attestationData = utils.toBase64url(response.attestationObject);
    }
    return registration;
}
exports.register = register;
async function getTransports(authType) {
    const local = ['internal'];
    // 'hybrid' was added mid-2022 in the specs and currently not yet available in the official dom types
    // @ts-ignore
    const roaming = ['hybrid', 'usb', 'ble', 'nfc'];
    if (authType === "local")
        return local;
    if (authType == "roaming" || authType === "extern")
        return roaming;
    if (authType === "both")
        return [...local, ...roaming];
    // the default case: "auto", depending on device capabilities
    try {
        if (await isLocalAuthenticator())
            return local;
        else
            return roaming;
    }
    catch (e) {
        return [...local, ...roaming];
    }
}
/**
 * Signs a challenge using one of the provided credentials IDs in order to authenticate the user.
 *
 * @param {string[]} credentialIds The list of credential IDs that can be used for signing.
 * @param {string} challenge A server-side randomly generated string, the base64 encoded version will be signed.
 * @param {Object} [options] Optional parameters.
 * @param {number} [options.timeout=60000] Number of milliseconds the user has to respond to the biometric/PIN check.
 * @param {'required'|'preferred'|'discouraged'} [options.userVerification='required'] Whether to prompt for biometric/PIN check or not.
 */
async function authenticate(credentialIds, challenge, options) {
    options = options ?? {};
    if (!utils.isBase64url(challenge))
        throw new Error('Provided challenge is not properly encoded in Base64url');
    const transports = await getTransports(options.authenticatorType ?? "auto");
    let authOptions = {
        challenge: utils.parseBase64url(challenge),
        rpId: window.location.hostname,
        allowCredentials: credentialIds.map(id => {
            return {
                id: utils.parseBase64url(id),
                type: 'public-key',
                transports: transports,
            };
        }),
        userVerification: options.userVerification ?? "required",
        timeout: options.timeout ?? 60000,
    };
    if (options.debug)
        console.debug(authOptions);
    let auth = await navigator.credentials.get({ publicKey: authOptions });
    if (options.debug)
        console.debug(auth);
    const response = auth.response;
    const authentication = {
        credentialId: auth.id,
        //userHash: utils.toBase64url(response.userHandle), // unreliable, optional for authenticators
        authenticatorData: utils.toBase64url(response.authenticatorData),
        clientData: utils.toBase64url(response.clientDataJSON),
        signature: utils.toBase64url(response.signature),
    };
    return authentication;
}
exports.authenticate = authenticate;
