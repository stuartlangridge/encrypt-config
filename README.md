# encrypt-config

A node.js module to encrypt a JSON config file with a password, so the encrypted config can be stored in source control.

## Usage

Create a JSON config file `config.json`:

```
{
    "players": {
        "barnes": 10,
        "grobbelaar": 1
    }
}
```

`encrypt-config` will read `config.json` and create `config.json.enc`. This `config.json.enc` file can then be added to source control.

Then, in your code:

```
var ec = require('encrypt-config');
ec.decrypt('config.json.enc', 'config.password', function(err, conf) {
    console.log(conf.players.barnes); // => 10
});
```

## More detailed usage

`encrypt-config` parameters:

* `--password_file`: a named password file (defaults to `config.password`). Will be created (and populated with a strong password) if not present
* `--config`: a valid JSON config file (defaults to `config.json`)
* `--encrypted_config`: the output encrypted file which can be committed to source control (defaults to adding `.enc` to the config file name)

You can use `encrypt-config` from code, as above: it exports two functions.

```
ec.decrypt('config.json.enc', 'config.password', function(err, conf) {
    console.log(conf.players.barnes); // => 10
});

ec.encrypt('config.json', config.json.enc', 'config.password', function(err) {
    console.log('Your config is now saved.');
});
```

Note that both functions take filenames, not plaintext strings, as parameters.

## Storing config details in source control is a terrible idea! Why do you encourage that?

Well, sometimes. If you don't like doing this, certainly don't do it. But having to set up the password once and then allow adding config to the repository is quite convenient.

`encrypt-config` will refuse to encrypt if the chosen password is not strong enough.

Be sure to commit only `config.json.enc` to source control and _not_ `config.json` or `config.password`. You will need to copy `config.password` to any live deployments.
