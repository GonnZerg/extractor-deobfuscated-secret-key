#     extractor-deobfuscated-secret-key

## extractor_deobfuscated_secret_key.py
Retrieves the data from this database as it would a real database and structures its contents into a hash line based on 1password2john's format.

## encryption_process.py
Takes values from encryption_test_setup.json to follow 1Password8's two-secret key derivation (2SKD) to form the MUK (Master Unlock Key, now called AUK in current documentation) with the encrypted password, account info, secret key, etc. The process is detailed in David Schuetz's 1Password series: https://darthnull.org/series/1password/

## Hash example
`$mobilekeychain$nobody@example.com$ef4b0bc381a687cfc6e3c8bbd94f636362bbebf5174f417f5d6b529595b8d533$16155981c440a00c3c260aa95c148fbdf11f0602dd11d5af477f62d0314fb23f$100000$d8517c9ad183e79cfce21f6332d580c9$f0e8ce03636a519646c570f8afecf84147f18efba4db7fe2d03140718c71d6bf38866b06d4a5751bd88a05977e905a5fcc381c8890f787c77dd4e4fd0fa17c295aaf766c7fabae3d996121896c15726465291573823f9e66e9d2d571f1c0760386f36f773294a4d740a7b10ab10091a62249dfe7939dd40114c772782c24c67a8c92e196df6e8ffe68d6e72a7fa98a467381e0a58fbfdda1212a298a54626ec4be08e54e4b53664554d3$61448c648c94a1b44c2d5dc4da5701fa`

`$signature$email$hkdf_salt$hkdf_key$iterations$iv$ct$tag`

## 1password.sqlite
Contains two tables: "accounts" and "account_objects".

### Accounts Table to extract account information
Contains one record, same as a real 1Password8 iOS sqlite database I based it on.
The data field contains a JSON text with some of the values removed to maintain the same structure except for those that are actually needed in the encryption of the MUK (Master Unlock Key) and symmetric key.

The secret key in this JSON is not stored as plain text and is "lightly obfuscated", as stated by 1Password on their White Paper, depending on client and client platform. I'm not familiar with how to deobfuscate this value so I don't retrieve this to use on extraction.py or on encryption_process.py, instead I use the example values shared by David Schuetz on his 1Password series, first found on this post "1Password - MUKing about on the Mac": https://darthnull.org/1pass-muking-about/

### Account Objects Table to extract first keyset
Contains one record. The real database I based it on contains multiple keysets and account records but only the first keyset is needed to decrypt the encrypted symmetric key. The rest are used to decrypt the actual vaults if I remember correctly.

I've browsed the 1password.sqlite database files of two 1Password8 iOS accounts and both have the first keyset in the first record of the "account_objects" table.
