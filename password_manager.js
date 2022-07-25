"use strict";

/********* External Imports ********/

const { byteArrayToString, genRandomSalt, untypedToTypedArray, bufferToUntypedArray } = require("./lib");
const { subtle } = require('crypto').webcrypto;


/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.

   * Return Type: void
   */
  constructor(masterPass, salt1p, salt2p, salt3p, ivp, keysp, kvsp, ivsp) {
    this.ready=false;

    var self = this;
    this.data = {

      salt1: salt1p,
      salt2: salt2p,
      salt3: salt3p,
      iv: ivp, 
      kvs: kvsp,
      ivs : ivsp
    };

    this.secrets = { 
      keys: keysp

    };

    this.data.version = ("CS 255 Password Manager v1.0");
    // Flag to indicate whether password manager is "ready" or not
    this.ready = true;
  };

  /*
  Get some key material to use as input to the deriveKey method.
  The key material is a password supplied by the user.
  */
  static async getKeyMaterial(password) {
    let enc = new TextEncoder();
    return subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits", "deriveKey"]
    );
  };

  /* Use PBKDF to get one secret key, HMAC to get two new ones from it.
  Works becayse HMAC is a PRNG*/
  static async getSecretKey(masterPass, salt1, salt2, salt3) {
    let keyMaterial = await Keychain.getKeyMaterial(masterPass);

    let masterKey = await subtle.deriveKey(
      {
        "name": "PBKDF2",
        salt: salt1,
        "iterations": this.PBKDF2_ITERATIONS,
        "hash": "SHA-256"
      },
      keyMaterial,
      { "name": "HMAC", length: 256, hash: {name: "SHA-256"},  "DOMString": "SHA-256"},
      true,
      [ "sign"]
    );


    let enc = new TextEncoder();
    let encoding1 = enc.encode(salt2);
    let encoding2 = enc.encode(salt3);
    let key1C = await subtle.sign(
      {name: "HMAC", hash: "SHA-256", length:256},
      masterKey,
      encoding1
    );
    let key2C = await subtle.sign(
      {name: "HMAC", hash: "SHA-256", length: 256},
      masterKey,
      encoding2
    );
    let key1M = await subtle.importKey(
      "raw",
      key1C,
      {name: "AES-GCM"},
      true, 
      ["encrypt", "decrypt"]
    );
    let key2M = await subtle.importKey(
      "raw",
      key1C,
      {name: "HMAC", hash: "SHA-256", length: 256},
      true, 
      ["sign"] 
    );
    var keys = {key1: key1M, key2: key2M}
    return keys
  };


  /**
    * Creates an empty keychain with the given password. Once the constructor
    * has finished, the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    const salt1 = genRandomSalt(64);
    const salt2 = genRandomSalt(64);
    const salt3 = genRandomSalt(64);
    const iv = genRandomSalt(16);
    const keys = await Keychain.getSecretKey(password, salt1, salt2, salt3);
    var keychain = new Keychain(password, salt1, salt2, salt3, iv, keys, {}, {});
    while(!keychain.ready) {}
    return keychain;
  };


  static async equal(buf1, buf2) {
    if (buf1.byteLength != buf2.byteLength) return false;
    var dv1 = new Int8Array(buf1);
    var dv2 = new Int8Array(buf2);
    for (var i = 0 ; i != buf1.byteLength ; i++)
    {
        if (dv1[i] != dv2[i]) return false;
    }
    return true;
  };


  /**
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    let sha = await subtle.digest("SHA-256", repr);
    if (trustedDataCheck !== undefined) {
     if (! Keychain.equal(sha, trustedDataCheck)) {
      console.log("checksum failed");
      return null;
     }
    }

    let reprN = JSON.parse(repr);



    const iv = genRandomSalt(16);
    let newkvs = await Keychain.kvsToBuffer(reprN['kvs']);

    const keys = await Keychain.getSecretKey(password, reprN['salts'].salt1, reprN['salts'].salt2, reprN['salts'].salt3);
    let keychain = new Keychain(password, reprN['salts'].salt1, reprN['salts'].salt2, reprN['salts'].salt3,
      iv, keys, newkvs, reprN['ivs'])

    while(!keychain.ready) {}
    return keychain;

  };

  static async kvsToBuffer(kvs) {
    let newKvs = {}
    let keys = Object.keys(kvs);
    for (let i =0; i < keys.length; i++) {
      newKvs[keys[i]] = untypedToTypedArray(kvs[keys[i]]);
    }
    return newKvs
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    *
    * Return Type: array
    */

  static async kvsToArrays(kvs){
    let ret = Object.entries(kvs);
    for (let i = 0; i < ret.length; i++ ){
      console.log('------');
      console.log(ret[i])
      ret[i] = [bufferToUntypedArray(ret[i][0]), bufferToUntypedArray(ret[i][0])];
      console.log(ret[i])
    }
    return ret;
  }

  async getJSONObj(){
    var salts2 = {}
    salts2.salt1 = this.data.salt1;
    salts2.salt2 = this.data.salt2;
    salts2.salt3 = this.data.salt3;

    let kvsD = {};
    let keys = Object.keys(this.data.kvs);
    for (let i=0; i< keys.length; i++) {//thorugh the keys, create a new kvs object.
 
      kvsD[keys[i]] = bufferToUntypedArray(this.data.kvs[keys[i]]);
    }
    var d = {"salts": salts2, "kvs" : kvsD, "ivs" : this.data.ivs};
    return d;
  };

  async dump() {

    if(!this.ready){
      return null;
    }
    let dumpData = await this.getJSONObj();

    let serial = await JSON.stringify(dumpData);

    let sha = await subtle.digest("SHA-256", serial);

    return [serial, sha];
  };

  //add if it doesn't fetch
  async getDomainHMAC(name){
    const encoder = new TextEncoder();
    const domaindata = encoder.encode(name);
    let domainHMAC = await subtle.sign(
      {name: "HMAC", hash: "SHA-256", length:256},
      this.secrets.keys.key2,
      domaindata
    );
    return domainHMAC;
  };

  /**
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {

    if(!this.ready){
      throw "KVS not initialized";
    }
    let domainHMAC = await this.getDomainHMAC(name);
    var encryptedData = this.data.kvs[byteArrayToString(domainHMAC)];
    if(! this.data.kvs.hasOwnProperty(byteArrayToString(domainHMAC))) {
      return null;
    }



      let decryptedData = await subtle.decrypt(
        {name: "AES-GCM",
        iv: this.data.ivs[byteArrayToString(domainHMAC)],
        additionalData: domainHMAC
      },
        this.secrets.keys.key1,
        encryptedData
      );
      let test = byteArrayToString(decryptedData);
      while(test.charAt(0)!="1"){

        test = test.substring(1);
      }
      test = test.substring(1);
      return test;


  };

  /**
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */


  async pad(pass) {

    return pass;
  };

  async unpad(pass) {
    while(pass.charAt(0)!="1"){
 
      pass = pass.substring(1);
    }
    pass = pass.substring(1);
  }

  async set(name, value) {

    value = "1" + value;
    while (value.length <= 64) {
      value = "0" + value;
    }
    if(!this.ready) {
      throw "KVS not ready";
    }
    let domainHMAC = await this.getDomainHMAC(name);

    const encoder = new TextEncoder();
    const passdata = encoder.encode(value);
    let domainPassEncryption = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: this.data.iv,
        additionalData: domainHMAC
      },
      this.secrets.keys.key1,
      passdata
    );

    this.data.kvs[byteArrayToString(domainHMAC)] = domainPassEncryption;
    this.data.ivs[byteArrayToString(domainHMAC)] = this.data.iv;
    this.data.iv = genRandomSalt(16); 

  };




  /**
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    if(!this.ready) {
      throw "Keychain not initialized";
    }
    let domainHMAC = await this.getDomainHMAC(name)
    let domainHMACstr = byteArrayToString(domainHMAC);
    if(this.data.kvs.hasOwnProperty(domainHMACstr)) {
      delete this.data.kvs[domainHMACstr];
      return true;
    }
    return false;
  };

  static get PBKDF2_ITERATIONS() { return 100000; }
};

module.exports = {
  Keychain: Keychain
}
