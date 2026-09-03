# Third-party notices

Network Sentinel itself is licensed under the MIT License — see [`LICENSE`](LICENSE).
This file covers everything else, and it is organised by the only question that
decides whether a licence obligation applies to you: **does the thing travel
inside a release artifact?**

| Section | Ships in the tarball / binary? | Obligation |
|---|---|---|
| [Redistributed components](#redistributed-components) | **Yes** | Their licence text must accompany the release — that is what this file is for |
| [Build and test only](#build-and-test-only) | No | None |
| [Data services used at runtime](#data-services-used-at-runtime) | No — each install fetches its own copy | Attribution and fair use |
| [Software the setup scripts install](#software-the-setup-scripts-install) | No — downloaded onto the target machine | None for this project |

The server package is built with `dotnet publish --self-contained true`
(`scripts/package.sh`), so the .NET runtime, Avalonia and the Inter typeface are
physically inside the artifact you hand someone. `scripts/package.sh` stages
`LICENSE` and this file into the tarball, and `scripts/install-from-package.sh`
installs both to `$PREFIX/share/doc/networksentinel/`, which is what keeps a
release compliant rather than just this repository.

---

## Redistributed components

### .NET 8 runtime and ASP.NET Core shared framework

Referenced as `Microsoft.AspNetCore.App` and embedded by the self-contained
publish. Kestrel backs the headless web console; `HttpListener` cannot serve TLS
on Linux.

```text
The MIT License (MIT)

Copyright (c) .NET Foundation and Contributors

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Microsoft's own redistribution terms for the .NET runtime are permissive; see
<https://dotnet.microsoft.com/platform/support/policy/dotnet-core>.

### Avalonia 11.2.5

`Avalonia`, `Avalonia.Desktop`, `Avalonia.Themes.Fluent`,
`Avalonia.Controls.DataGrid`, `Avalonia.Fonts.Inter` — the cross-platform UI
toolkit behind the desktop GUI. <https://github.com/AvaloniaUI/Avalonia>

```text
The MIT License (MIT)

Copyright (c) AvaloniaUI OÜ
All Rights Reserved

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Inter typeface (via `Avalonia.Fonts.Inter`)

The NuGet package is MIT-licensed like the rest of Avalonia, but the **font
files it embeds are licensed separately, under the SIL Open Font License 1.1**,
which requires this copyright notice and licence to accompany the font. The
self-contained binary contains those font files, so the notice belongs here.

`Inter` is a Reserved Font Name under the OFL: a modified version of the
typeface may not be distributed under that name.

<https://github.com/rsms/inter>

```text
Copyright (c) 2016 The Inter Project Authors (https://github.com/rsms/inter)

This Font Software is licensed under the SIL Open Font License, Version 1.1.
This license is copied below, and is also available with a FAQ at:
http://scripts.sil.org/OFL

-----------------------------------------------------------
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
-----------------------------------------------------------

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION AND CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created
using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```

### CommunityToolkit.Mvvm 8.4.0

MVVM source generators and observable primitives used by the view models.
<https://github.com/CommunityToolkit/dotnet>

```text
# .NET Community Toolkit

Copyright © .NET Foundation and Contributors

All rights reserved.

## MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

### Spectre.Console 0.49.1

Renders the terminal UI (`--tui`). <https://github.com/spectreconsole/spectre.console>

```text
MIT License

Copyright (c) 2020 Patrik Svensson, Phil Scott, Nils Andresen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Build and test only

These are referenced by the test project or the CI workflow. Nothing here is
redistributed, so no notice obligation attaches to a release — they are listed
for completeness.

| Component | Licence | Used by |
|---|---|---|
| xunit 2.6.6, xunit.runner.visualstudio 2.5.6 | Apache-2.0 | `Tests/NetworkSentinel.Tests` |
| Microsoft.NET.Test.Sdk 17.8.0 | MIT | `Tests/NetworkSentinel.Tests` |
| `actions/checkout@v4`, `actions/setup-dotnet@v4` | MIT | `.github/workflows/ci.yml` |

---

## Data services used at runtime

These are **not** redistributed. Each installation fetches its own copy at
runtime and caches it locally under `~/.local/share/NetworkSentinel`, so the
data never travels inside a release artifact. Attribution and fair-use terms
still apply to the fetching, and the terms below bind whoever runs the software.

### FireHOL `firehol_level1`

`Services/ThreatIntelService.cs` fetches
<https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset>
once a day.

The FireHOL tooling is GPLv2, but the IP lists are the property of their
respective maintainers, and `firehol_level1` is an aggregate: it includes
**DShield** (SANS Internet Storm Center), **Feodo** (abuse.ch), **fullbogons**
(Team Cymru) and **Spamhaus DROP**. Consult those maintainers' terms before
using the data for anything beyond what this app does with it.

- <https://iplists.firehol.org/>
- <https://github.com/firehol/blocklist-ipsets>

### Spamhaus DROP (Don't Route Or Peer)

`Services/ThreatIntelService.cs` fetches <https://www.spamhaus.org/drop/drop.txt>
once a day.

**The DROP list data is the copyright and database right of The Spamhaus
Project.** It is provided free of charge, and this application uses it under
Spamhaus' published terms. If you redistribute the plain-text feed you must name
Spamhaus as the source and retain the copyright statement and timestamps at the
top of the file. The "Spamhaus" name may not be used in marketing or
promotional material.

- Usage terms: <https://www.spamhaus.org/drop/terms/>
- Fair use policy: <https://www.spamhaus.org/blocklists/drop-fair-use-policy/>

Note that `firehol_level1` above already contains `spamhaus_drop`, so the two
configured feeds overlap.

### IP geolocation — ipwho.is and ipapi.co

`Services/GeoIpService.cs` resolves the country, city and ISP of a public peer
through <https://ipwho.is/>, falling back to <https://ipapi.co/> — both keyless
free endpoints, called from the machine running Network Sentinel.

**Both providers scope their free tiers to non-commercial or development use and
enforce per-day request caps.** Enabling geolocation means accepting those
providers' terms, and it is your responsibility as the operator to hold a paid
plan if your use falls outside them:

- <https://ipwhois.io/terms>
- <https://ipapi.co/terms/>

Reverse DNS in the same service uses the host resolver and involves no
third party.

---

## Software the setup scripts install

`scripts/setup-dns-filter.sh` and `scripts/issue-duckdns-cert.sh` download and
install these **onto the target machine at run time**. None of them is bundled
in, linked against, or derived from by Network Sentinel, so their licences —
including the copyleft ones — do not reach this project's own code. They are
listed so an operator knows what lands on the host.

| Software | Licence | Installed by |
|---|---|---|
| AdGuard Home | GPLv3 | `setup-dns-filter.sh` (from the project's GitHub releases, checksum-verified) |
| AdGuard base / malware filter lists, Phishing Army, PhishTank + OpenPhish, NoCoin, DoH bootstrap list | per-list terms of their maintainers | `setup-dns-filter.sh`, then fetched by AdGuard Home itself |
| acme.sh | GPLv3 | `issue-duckdns-cert.sh` |
| Let's Encrypt (ACME service) | service terms | `issue-duckdns-cert.sh` |
| DuckDNS (dynamic DNS service) | service terms | `Services/DuckDnsUpdater.cs`, when configured |

**Suricata** (GPLv2) is likewise never bundled. Network Sentinel only tails the
`eve.json` file a separately installed Suricata writes; you install, configure
and license Suricata yourself.

The host tools the app shells out to — `nft`, `iptables`, `ufw`, `ss`, `pkexec`,
`sudo`, `journalctl` — are part of the operating system and are neither shipped
nor modified.
