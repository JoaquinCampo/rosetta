# Rosetta

A universal data decoder for the command line. Pipe in any opaque data and Rosetta figures out what it is.

```
$ rosetta "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

JWT Token  ●●●

  Algorithm  HS256
       Type  JWT
    Subject  1234567890
  Issued At  2018-01-18 01:30:22 UTC
    Payload:
      {
        "iat": 1516239022,
        "name": "John Doe",
        "sub": "1234567890"
      }
```

## Install

```
cargo install --git https://github.com/JoaquinCampo/rosetta
```

## Usage

Pass data as an argument or pipe it in:

```
rosetta <data>
echo <data> | rosetta
```

Rosetta auto-detects the format and shows you what's inside. When multiple formats match, results are ranked by confidence.

## Examples

**Timestamps**
```
$ rosetta 1705312200

Unix Timestamp  ●●○

       Format  Unix timestamp (seconds)
          UTC  2024-01-15 09:50:00.000 UTC
        Local  2024-01-15 05:50:00 EST
     ISO 8601  2024-01-15T09:50:00+00:00
  Day of Week  Monday
     Relative  1 year ago
```

**Cron expressions**
```
$ rosetta "0 */6 * * *"

Cron Expression  ●●●

    Expression  0 */6 * * *
   Description  Every 6 hours
   Next 5 runs:
     2026-03-03 06:00 UTC
     2026-03-03 12:00 UTC
     ...
```

**Colors**
```
$ rosetta "#ff6b35"

Color Value  ●●●

             Format  Hex (#6 chars)
                Hex  #ff6b35
                RGB  rgb(255, 107, 53)
                HSL  hsl(16, 100%, 60%)
       Closest Name  Tomato
  Contrast vs White  2.84:1 (Fail)
  Contrast vs Black  7.41:1 (AAA)
```

**Network**
```
$ rosetta 192.168.1.0/24

CIDR Notation  ●●●

        Network  192.168.1.0/24
    Subnet Mask  255.255.255.0
  Wildcard Mask  0.0.0.255
      Broadcast  192.168.1.255
   First Usable  192.168.1.1
    Last Usable  192.168.1.254
   Usable Hosts  254
```

**UUIDs**
```
$ rosetta "550e8400-e29b-41d4-a716-446655440000"

UUID  ●●●

     UUID  550e8400-e29b-41d4-a716-446655440000
  Version  4 (Random)
  Variant  RFC 4122
```

**Base64**
```
$ echo "SGVsbG8gV29ybGQ=" | rosetta

Base64  ●●○

      Decoded  Hello World
  Byte length  11
     Encoding  Standard (RFC 4648)
```

**HTTP status codes**
```
$ rosetta 404

HTTP Status Code  ●●○

         Code  404
         Name  Not Found
     Category  Client Error
  Description  Requested resource could not be found on the server
```

**File permissions**
```
$ rosetta 755

Unix Permissions  ●●○

     Symbolic  rwxr-xr-x
        Owner  read, write, execute
        Group  read, execute
        Other  read, execute
  Common Name  Standard directory / executable
```

## Supported Formats

| Format | Example |
|--------|---------|
| JWT tokens | `eyJhbGciOi...` |
| Base64 | `SGVsbG8gV29ybGQ=` |
| Hex strings | `0x48656c6c6f` |
| URL encoding | `hello%20world` |
| Unix timestamps | `1705312200` |
| Cron expressions | `0 */6 * * *` |
| ISO 8601 dates | `2024-01-15T10:30:00Z` |
| Durations | `PT1H30M`, `3h30m` |
| IPv4/IPv6 addresses | `10.0.0.1`, `::1` |
| CIDR notation | `192.168.1.0/24` |
| UUIDs | `550e8400-e29b-41d4-...` |
| URLs | `https://example.com/path?q=1` |
| Hashes (MD5/SHA) | `d41d8cd98f00b204...` |
| Docker images | `ghcr.io/user/app:v1.2` |
| CSS colors | `#ff6b35`, `rgb(255,107,53)` |
| Semantic versions | `1.2.3-beta.1` |
| HTTP status codes | `404`, `200`, `503` |
| Unix permissions | `755`, `0644` |

## How It Works

Rosetta runs every detector against your input simultaneously. Each detector returns a confidence score (0.0–1.0) based on how well the input matches. Results are displayed from highest to lowest confidence, so the most likely interpretation appears first.

No flags, no modes, no configuration. Just data in, meaning out.

## License

MIT
