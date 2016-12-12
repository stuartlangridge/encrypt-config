var crypto = require('crypto');
var algorithm = 'aes-256-ctr';
var fs = require("fs");
var zxcvbn = require("zxcvbn");

module.exports = {
    algorithm: algorithm,
    decrypt: function(encryptedConfigPath, passwordPath, done) {
        fs.readFile(encryptedConfigPath, function(err, enc_conf_buffer) {
            if (err) return done(err);
            fs.readFile(passwordPath, {encoding: "utf-8"}, function(err, password) {
                if (err) return done(err);
                var decipher = crypto.createDecipher(algorithm, password);
                var dec = Buffer.concat([decipher.update(enc_conf_buffer), decipher.final()]);
                var j;
                var s = dec.toString("utf-8"); // this can't fail; it will put unknown char markers in
                try {
                    j = JSON.parse(s);
                } catch(e) {
                    e.message = "Decrypted config did not seem to be valid JSON";
                    e.code = "NONJSON";
                    return done(e);
                }
                done(null, j);
            });
        });
    },
    encrypt: function(decryptedConfigPath, encryptedConfigPath, passwordPath, done) {
        fs.readFile(passwordPath, {encoding: "utf-8"}, function(err, password) {
            if (err) return done(err);

            var res = zxcvbn(password);
            if (res.score < 4) {
                var msg = [];
                if (res.feedback.warning) msg.push(res.feedback.warning);
                if (res.feedback.suggestions && res.feedback.suggestions.length > 0) {
                    msg = msg.concat(res.feedback.suggestions);
                }
                if (msg.length == 0) {
                    msg = ["The chosen password was not strong enough. You must choose a stronger password, " +
                        "in order to keep your config in source control safe."];
                }
                var e = new Error(msg.join("\n"));
                e.code = "WEAK";
                return done(e);
            }

            fs.readFile(decryptedConfigPath, {encoding: "utf-8"}, function(err, dec_conf) {
                if (err) return done(err);
                try {
                    JSON.parse(dec_conf);
                } catch(e) {
                    var err = new Error("Supplied config ('" + decryptedConfigPath + "') " +
                        "is not valid JSON ('" + e.message + "')");
                    err.code = "NONJSON";
                    return done(err);
                }
                var cipher = crypto.createCipher(algorithm, password);
                var crypted = Buffer.concat([cipher.update(dec_conf), cipher.final()]);
                fs.writeFile(encryptedConfigPath, crypted, done);
            });
        });
    }
}