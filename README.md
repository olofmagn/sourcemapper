# JavaScript Source-Map Secrets & Endpoint Extractor (sourcemapper)

Reconstruct the original source tree from a `.js.map` sourcemap and scan the contents for endpoints, URLs, routes, environment variables, secrets, and other security-relevant patterns with high confidence.

Clone the repository:
```bash
git clone https://github.com/olofmagn/sourcemapper.git
```

Install python requirements:
```bash
pip3 install -r requirements.txt
```

Run against a `.js.map` sourcemap (URL or local file path):
```bash
python3 sourcemapper.py "https://target.com/static/js/test-js.map" -o app_src
```

The tool first reconstructs the embedded source tree:
```
[~] 📂 Extracting https://target.com/static/js/test-js.map
--------------------------------------------
[+] 📄 14 sources in map
[+] ✅ Extracted 13 files to: /home/olofmagn/Projects/sourcemapper/app_src
--------------------------------------------
[~] 🔍 Scanning 11 recovered sources with 80 rules
```

The extracted source tree is available in the specified output directory:
```
app_src/
├── src/
│   ├── api/
│   │   ├── client.js
│   │   └── webhooks.js
│   ├── config/
│   │   ├── aws.js
│   │   ├── db.js
│   │   └── secrets.js
│   ├── legacy/
│   │   └── upload.js
│   ├── net/
│   │   └── misc.js
│   ├── routes/
│   │   └── routes.js
│   └── vendor/
│       ├── extra.js
│       └── extra2.js
└── ...
```

The tool scans the recovered source contents with configured rules in `scan_patterns.yaml`. Findings are then grouped by rule and each match includes the original source path, line number, and matching line:

```
[~] Extracting test-js.map
[+] 14 sources in map
[+] Extracted 13 files to: app_src 
[~] Scanning 11 recovered sources with 80 rules
 
[AWS access key id] 1
  src/config/aws.js:2  const AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP";
 
[Discord webhook] 1
  src/api/webhooks.js:2  const webhook = "https://discord.com/api/webhooks/123456789012345678/abcDEF-ghiJKL";
 
[Private key header (PEM)] 1
  src/config/aws.js:7  -----BEGIN RSA PRIVATE KEY-----
 
[JWT] 1
  src/config/secrets.js:6  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ_abcdefgh";
 
[Credentials embedded in URL] 5
  src/config/db.js:2  const mongoUri = "mongodb+srv://user:pass@cluster0.mongodb.net/mydb";
  src/config/db.js:3  const pgUri = "postgres://user:pass@db.example.com:5432/mydb";
  src/config/db.js:4  const mysqlUri = "mysql://root:toor@localhost:3306/app";
  src/config/db.js:5  const redisUri = "redis://default:pw@cache.example.com:6379";
  src/config/db.js:7  const credUrl = "https://admin:S3cret!@legacy.example.com/panel";
 
[MongoDB connection string] 1
  src/config/db.js:2  const mongoUri = "mongodb+srv://user:pass@cluster0.mongodb.net/mydb";
 
[Azure host (blob / websites / api)] 1
  src/vendor/extra2.js:20  const azureHost = "mystorageacct.blob.core.windows.net";
 
[Internal hostname (scheme-qualified)] 1
  src/net/misc.js:5  const internalHost = "https://svc.internal.corp.local/health";
 
[ASP.NET endpoint (.asmx/.ashx/.aspx)] 2
  src/legacy/upload.js:4  const aspxHandler = "handlers/FileManager.ashx?action=list";
  src/legacy/upload.js:5  const asmxSvc = "webservices/Auth.asmx/Login";
 
[Environment variable] 1
  src/net/misc.js:8  process.env.DATABASE_URL;
 
[TODO / FIXME / HACK dev note] 1
  src/net/misc.js:7  // TODO: remove this before shipping
...
--------------------------------------------
[~] 115 findings across categories
[+] Report written to: /home/olofmagn/Projects/sourcemapper/report.txt
```

## Note
Third-party `node_modules` sources are excluded from automated scanning to reduce noise, but are still reconstructed into the output tree so they can be inspected manually if necessary.

## Credits
The scan rules are based partly on patterns from:
- [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db)
- [SecretFinder](https://github.com/m4ll0k/SecretFinder)
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder)
- [Search-for-all-leaked-keys-secrets-using-one-regex-](https://github.com/Lu3ky13/Search-for-all-leaked-keys-secrets-using-one-regex-)


> [!WARNING]
> This content is provided for educational and authorized security testing purposes only.