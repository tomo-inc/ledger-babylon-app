# Bug Tracking Table

| NO  | LEVEL  | NAME                                          | comment                                   | solution                                    |
|-----|--------|-----------------------------------------------|-------------------------------------------|---------------------------------------------|
| 1   | LOW    | Buffer overrun                                | Ledger's musigsession_commit code        | Done. Delete all musig code                |
| 2   | HIGH   | Removed validation checks                     | fix April 3th  105a8c0                   | Done.                                      |
| 3   | HIGH   | Insecure policy name matching                 |                                           | Done. Add new function to check descriptor |
| 4   | Medium | Infinite point check missing                  | Ledger's musig code                      | Done. Delete all musig code                |
| 5   | LOW    | Outdated documentation                        |                                           | Done. As recommendation                    |
| 6   | LOW    | Hardcoded constants                           | Ledger's musig Hardcoded                 | Done. Delete all musig code                |
| 7   | LOW    | Insecure string copying                       | Ledger's UI code                         | Suggest to ignore                          |
| 8   | HIGH   | Lack of fee and output validations            | There are ways to do validations         | Please search ‘BAP-008’ in code            |
| 9   | LOW    | flawed fingerprint policy                     | fingerprint has special using            | Please search ‘BAP-009’ in code            |
| 10  | LOW    | Insufficient input validation                 | There are ways to do validations         | Please search ‘BAP-010’ in code            |
| 11  | HIGH   | Insufficient SIGHASH TYPE enforcement         |                                           | Done. As recommendation                    |
