var crypto = require("crypto");
var tap = require("tap");
var mock = require('mock-fs');
var fs = require("fs");
var ec = require("../lib/encrypt-config");

tap.test('basic tests', function(t) {
  t.plan(3);

  t.beforeEach(function(done) { mock(); done(); });
  t.afterEach(function(done) { mock.restore(); done(); })

  var basicPassword = "94wht0gh03vb8h083hg038hnc08hnc0vnhcv0iwcvnoipwevunwiovn";
  var basicConfig = {thing: "yes"};
  var basicEncryptedBuffer = Buffer([0xbe, 0xe8, 0xda, 0xf1, 0x77, 0x7a, 0xb9, 0xb7, 0xcf, 
    0x54, 0x16, 0x9d, 0xb2, 0x15, 0x57]);

  t.test('basic encryption', function(t) {
    var plainConfigPath = "temporaryWrittenConfig.json";
    var encConfigPath = "temporaryWrittenConfig.json.enc";
    var passwordPath = "passwordfile";
    fs.writeFile(plainConfigPath, JSON.stringify(basicConfig), {encoding: "utf-8"}, function(err) {
      if (err) throw(err);

      // write the password to a file
      fs.writeFile(passwordPath, basicPassword, {encoding: "utf-8"}, function(err) {
        if (err) throw(err);

        // encrypt the config
        ec.encrypt(plainConfigPath, encConfigPath, passwordPath, function(err) {
          if (err) throw(err);

          fs.readFile(encConfigPath, function(err, buf) {
            if (err) throw(err);

            t.deepEqual(buf, basicEncryptedBuffer);
            t.end();

          });

        });
      });
    });
  });

  t.test('basic decryption', function(t) {
    var encConfigPath = "temporaryWrittenConfig.json.enc";
    var passwordPath = "passwordfile";
    fs.writeFile(encConfigPath, basicEncryptedBuffer, function(err) {
      if (err) throw(err);

      // write the password to a file
      fs.writeFile(passwordPath, basicPassword, {encoding: "utf-8"}, function(err) {
        if (err) throw(err);

        // encrypt the config
        ec.decrypt(encConfigPath, passwordPath, function(err, decryptedConfig) {
          if (err) throw(err);

          t.deepEqual(decryptedConfig, basicConfig);
          t.end();

        });
      });
    });
  });

  t.test('encrypt a config file and decrypt it', function(t) {
    // write our example config to a file
    var config = {one: "two", five: 6, somebool: true, nested: {n1: 1, n2: 2}, list: [1,2,"a list"]};
    var password = "93tvhn90fhc90hn3-9tvhn23-9c3hfn9-3hx-2mh2-9h32vng";
    var plainConfigPath = "temporaryWrittenConfig.json";
    var encConfigPath = "temporaryWrittenConfig.json.enc";
    var passwordPath = "passwordfile";
    fs.writeFile(plainConfigPath, JSON.stringify(config), {encoding: "utf-8"}, function(err) {
      if (err) throw(err);

      // write the password to a file
      fs.writeFile(passwordPath, password, {encoding: "utf-8"}, function(err) {
        if (err) throw(err);

        // encrypt the config
        ec.encrypt(plainConfigPath, encConfigPath, passwordPath, function(err) {
          if (err) throw(err);

          // decrypt the config
          ec.decrypt(encConfigPath, passwordPath, function(err, decryptedConfig) {
            if (err) throw(err);

            t.deepEqual(config, decryptedConfig);
            t.end();

          });

        })

      });

    })
  });

});

tap.test('getting it right', function(t) {
  t.plan(8);

  var existingPassword = "497thvnc0f7280x2hf24n80fh08f72802cf8nhxn2";
  t.beforeEach(function(done) {
    mock({
      "existingPasswordFile": existingPassword,
      "existingDecryptedConfigFile": JSON.stringify({this_config: "exists", "true is": true}),
      "existingWeakPasswordFile": "passw0rd",
      "nonJSONPlaintextConfigFile": "ha ha ha ha not json",
      "existingWeakishPasswordFile": "g$d%saasd", // score=3. Not strong enough.
      "existingEncryptedConfigFile": Buffer([0xbe, 0xe8, 0xda, 0xf1, 0x77, 0x7a, 0xb9, 0xb7, 0xcf, 
        0x54, 0x16, 0x9d, 0xb2, 0x15, 0x57])
    }); 
    done();
  });
  t.afterEach(function(done) { mock.restore(); done(); })

  t.test('password file must exist when encrypting', function(t) {
    ec.encrypt("existingDecryptedConfigFile", "newEncryptedPasswordFile", "nonexistentPasswordFile", function(err) {
      t.equal(err.code, "ENOENT");
      t.end();
    })
  });

  t.test('password file must exist when decrypting', function(t) {
    ec.decrypt("existingEncryptedPasswordFile", "nonexistentPasswordFile", function(err) {
      t.equal(err.code, "ENOENT");
      t.end();
    })
  });

  t.test('insist on strong passwords', function(t) {
    ec.encrypt("existingDecryptedConfigFile", "newEncryptedPasswordFile", "existingWeakPasswordFile", function(err) {
      t.equal(err.code, "WEAK");
      t.end();
    })
  });

  t.test('insist on actually strong passwords', function(t) {
    ec.encrypt("existingDecryptedConfigFile", "newEncryptedPasswordFile", "existingWeakishPasswordFile", function(err) {
      t.equal(err.code, "WEAK");
      t.end();
    })
  });

  t.test('plaintext config file must exist when encrypting', function(t) {
    ec.encrypt("nonexistentPlainConfigFile", "newEncryptedPasswordFile", "existingPasswordFile", function(err) {
      t.equal(err.code, "ENOENT");
      t.end();
    })
  });

  t.test('encrypted config file must exist when decrypting', function(t) {
    ec.decrypt("nonexistentEncryptedPasswordFile", "existingPasswordFile", function(err) {
      t.equal(err.code, "ENOENT");
      t.end();
    })
  });

  t.test('config file to encrypt must be valid json', function(t) {
    ec.encrypt("nonJSONPlaintextConfigFile", "newEncryptedPasswordFile", "existingPasswordFile", function(err) {
      t.equal(err.code, "NONJSON");
      t.end();
    })
  });

  t.test('decrypting non-JSON', function(t) {
    // encrypt some non-JSON data
    var encryptedConfigPath = "somedata.json.enc";  
    var cipher = crypto.createCipher(ec.algorithm, existingPassword);
    var crypted = Buffer.concat([cipher.update("ha ha not JSON"), cipher.final()]);
    fs.writeFile(encryptedConfigPath, crypted, function(err) {
      if (err) throw err;
      ec.decrypt(encryptedConfigPath, "existingPasswordFile", function(err, decryptedConfig) {
        t.equal(err.code, "NONJSON");
        t.end();
      });
    });
  });

});