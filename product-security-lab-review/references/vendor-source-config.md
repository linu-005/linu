# Vendor Source Config

Use `scripts/fetch_vendor_releases.py --config <file>` with either:

- a top-level JSON array
- or an object with a `targets` array

Each target supports these fields:

- `url`: required, official release, changelog, download, or advisory page
- `vendor`: optional label
- `product`: optional label
- `mode`: `auto`, `feed`, or `html`
- `keywords`: optional string array used to keep only relevant release items
- `title_pattern`: optional regex for titles
- `href_pattern`: optional regex for URLs
- `exclude_patterns`: optional regex array to drop noisy entries
- `limit`: optional integer, max items per source

Example:

```json
{
  "targets": [
    {
      "vendor": "Python",
      "product": "Python Blog",
      "url": "https://blog.python.org/",
      "mode": "auto",
      "keywords": ["release", "security"],
      "exclude_patterns": ["jobs", "podcast"],
      "limit": 5
    }
  ]
}
```
