# Encrypted-Password-Manager

In this project, I built an encrypted password manager written in JavaScript. The password manager stores a KVS of user's usernames and passwords and can be unlocked using a master password. Each value / password entry is individually encrypted using AES-GCM. Each key / username entry is encryped using a HMAC. To derive keys from the master password, we use the PBKDF2 password-based key derivation function. 
