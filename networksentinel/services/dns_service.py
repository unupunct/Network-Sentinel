"""DNS resolver, cache and query monitor.

Three observation sources, all real:

``resolver``
    Every name the application itself resolves (reverse lookups, domain
    enrichment for observed connections) goes through a small TTL cache here,
    so a name is only ever shown when a real DNS answer produced it.

``passive``
    When raw capture is available, DNS packets on UDP/TCP 53 are decoded with
    dnspython.  This only sees *unencrypted* DNS.  With DoH/DoT (encrypted DNS),
    a VPN or a proxy, queries are invisible and the UI says so.

``agent``
    The managed-computer agent reports the DNS cache of the computer it runs
    on (Windows: ``Get-DnsClientCache``, Linux: ``resolvectl`` / systemd-resolved
    cache).  Those entries are marked as coming from an agent.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass

from networksentinel.core.logging import get_logger

log = get_logger(__name__)

try:  # dnspython is optional at import time
    import dns.message
    import dns.name
    import dns.rdatatype

    HAS_DNSPYTHON = True
except Exception:  # pragma: no cover - optional dependency
    HAS_DNSPYTHON = False

MAX_CACHE = 20000

#: Domain categories.  Matching is by suffix and is deliberately conservative:
#: a domain that matches nothing is reported as "Unknown destination".
CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("Search engines", (
        "google.com", "google.ro", "googleapis.com", "gstatic.com", "bing.com",
        "duckduckgo.com", "yahoo.com", "yandex.com", "yandex.ru", "baidu.com",
        "ecosia.org", "startpage.com", "search.brave.com", "qwant.com",
    )),
    ("Social networks", (
        "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com",
        "twitter.com", "x.com", "twimg.com", "t.co", "linkedin.com", "licdn.com",
        "reddit.com", "redd.it", "redditmedia.com", "tiktok.com", "tiktokcdn.com",
        "snapchat.com", "sc-cdn.net", "pinterest.com", "pinimg.com", "tumblr.com",
        "discord.com", "discordapp.com", "discord.gg", "discord.media",
        "telegram.org", "t.me", "whatsapp.com", "whatsapp.net", "vk.com",
        "mastodon.social", "threads.net", "bsky.app", "bsky.social",
    )),
    ("Video streaming", (
        "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "yt3.ggpht.com",
        "netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net",
        "twitch.tv", "ttvnw.net", "jtvnw.net", "primevideo.com", "aiv-cdn.net",
        "disneyplus.com", "dssott.com", "hbomax.com", "max.com", "hulu.com",
        "crunchyroll.com", "vimeo.com", "dailymotion.com", "plex.tv", "plex.direct",
        "spotify.com", "scdn.co", "spotifycdn.com", "soundcloud.com",
        "deezer.com", "tidal.com", "music.apple.com", "itunes.apple.com",
    )),
    ("Gaming", (
        "steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com",
        "steamserver.net", "valvesoftware.com", "epicgames.com", "unrealengine.com",
        "easyanticheat.net", "battle.net", "blizzard.com", "blzstatic.cn",
        "riotgames.com", "riotcdn.net", "leagueoflegends.com", "playvalorant.com",
        "ea.com", "origin.com", "eaassets-a.akamaihd.net", "ubisoft.com",
        "ubi.com", "rockstargames.com", "take2games.com", "playstation.com",
        "playstation.net", "xboxlive.com", "xbox.com", "nintendo.net",
        "nintendo.com", "minecraft.net", "mojang.com", "roblox.com", "rbxcdn.com",
        "gog.com", "gog-statics.com", "humblebundle.com", "faceit.com",
    )),
    ("Shopping", (
        "amazon.com", "amazon.co.uk", "amazon.de", "media-amazon.com", "ssl-images-amazon.com",
        "ebay.com", "ebayimg.com", "aliexpress.com", "alibaba.com", "alicdn.com",
        "emag.ro", "allegro.pl", "etsy.com", "walmart.com", "target.com",
        "bestbuy.com", "ikea.com", "temu.com", "shein.com", "shopify.com",
        "paypal.com", "stripe.com", "olx.ro", "flipkart.com",
    )),
    ("News", (
        "bbc.co.uk", "bbc.com", "cnn.com", "nytimes.com", "theguardian.com",
        "reuters.com", "bloomberg.com", "wsj.com", "washingtonpost.com",
        "digi24.ro", "hotnews.ro", "ziare.com", "adevarul.ro", "protv.ro",
        "euronews.com", "aljazeera.com", "dw.com", "lemonde.fr", "spiegel.de",
        "foxnews.com", "msnbc.com", "apnews.com", "politico.com",
    )),
    ("Cloud services", (
        "microsoft.com", "windowsupdate.com", "windows.com", "msftconnecttest.com",
        "msftncsi.com", "live.com", "office.com", "office365.com", "sharepoint.com",
        "onedrive.com", "1drv.com", "azure.com", "azureedge.net", "azurewebsites.net",
        "cloudfront.net", "amazonaws.com", "awsstatic.com", "elasticbeanstalk.com",
        "googleusercontent.com", "1e100.net", "appspot.com", "cloud.google.com",
        "dropbox.com", "dropboxstatic.com", "dropboxusercontent.com",
        "box.com", "icloud.com", "icloud-content.com", "microsoftonline.com",
        "akamai.net", "akamaiedge.net", "akamaized.net", "fastly.net",
        "cloudflare.com", "cloudflare-dns.com", "digitalocean.com", "linode.com",
        "hetzner.com", "ovh.net", "backblaze.com", "mega.nz", "pcloud.com",
    )),
    ("Email", (
        "gmail.com", "mail.google.com", "outlook.com", "hotmail.com", "outlook.office365.com",
        "yahoo.com", "protonmail.com", "proton.me", "mail.ru", "yandex.ru",
        "zoho.com", "mailchimp.com", "sendgrid.net", "mx.google.com",
    )),
    ("Development platforms", (
        "github.com", "githubusercontent.com", "githubassets.com", "github.io",
        "gitlab.com", "bitbucket.org", "npmjs.com", "npmjs.org", "pypi.org",
        "pythonhosted.org", "nuget.org", "docker.com", "docker.io", "dockerhub.com",
        "stackoverflow.com", "stackexchange.com", "sstatic.net", "jetbrains.com",
        "visualstudio.com", "vscode.dev", "vercel.com", "netlify.app", "heroku.com",
        "huggingface.co", "openai.com", "anthropic.com", "claude.ai",
        "cursor.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
        "readthedocs.io", "crates.io", "go.dev", "golang.org",
    )),
    ("Entertainment", (
        "imdb.com", "rottentomatoes.com", "spotify.com", "tumblr.com",
        "9gag.com", "imgur.com", "deviantart.com", "artstation.com",
        "wattpad.com", "goodreads.com", "letterboxd.com", "fandom.com",
        "wikia.com", "pinterest.com", "boredpanda.com",
    )),
    ("Advertising and tracking", (
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "adservice.google.com", "adnxs.com", "criteo.com", "criteo.net",
        "taboola.com", "outbrain.com", "scorecardresearch.com", "quantserve.com",
        "facebook.net", "connect.facebook.net", "moatads.com", "rubiconproject.com",
        "pubmatic.com", "adsrvr.org", "amazon-adsystem.com", "hotjar.com",
        "mixpanel.com", "segment.io", "amplitude.com", "bugsnag.com",
    )),
    ("Remote access", (
        "teamviewer.com", "anydesk.com", "rustdesk.com", "logmein.com",
        "gotomypc.com", "screenconnect.com", "connectwise.com", "splashtop.com",
        "parsec.app", "parsecgaming.com", "vnc.com", "realvnc.com", "nomachine.com",
    )),
    ("Operating system updates", (
        "update.microsoft.com", "delivery.mp.microsoft.com", "definitionupdates.microsoft.com",
        "apple.com", "apple-dns.net", "mzstatic.com", "swscan.apple.com",
        "ubuntu.com", "archive.ubuntu.com", "security.ubuntu.com", "canonical.com",
        "debian.org", "deb.debian.org", "fedoraproject.org", "archlinux.org",
        "packages.microsoft.com", "snapcraft.io", "flathub.org",
    )),
]

_LOCAL_SUFFIXES = (".local", ".lan", ".home", ".localdomain", ".internal", ".home.arpa")


def categorize(domain: str | None) -> str:
    if not domain:
        return "Unknown destination"
    name = domain.lower().rstrip(".")
    for category, suffixes in CATEGORIES:
        for suffix in suffixes:
            if name == suffix or name.endswith("." + suffix):
                return category
    if name.endswith(_LOCAL_SUFFIXES) or "." not in name:
        return "Local network"
    return "Unknown destination"


def is_local_name(domain: str | None) -> bool:
    if not domain:
        return False
    name = domain.lower().rstrip(".")
    return name.endswith(_LOCAL_SUFFIXES) or "." not in name


@dataclass
class ResolvedName:
    name: str
    addresses: list[str]
    ttl: float
    source: str
    ts: float

    @property
    def expired(self) -> bool:
        return time.time() > self.ts + self.ttl


class DnsResolver:
    """TTL-aware cache in front of the system resolver."""

    def __init__(self) -> None:
        self._by_ip: dict[str, ResolvedName] = {}
        self._by_name: dict[str, ResolvedName] = {}
        self._lock = threading.Lock()
        self.queries = 0
        self.hits = 0

    def _evict(self) -> None:
        if len(self._by_ip) < MAX_CACHE:
            return
        for key in list(self._by_ip)[: MAX_CACHE // 4]:
            self._by_ip.pop(key, None)

    def resolve(self, hostname: str, ttl: float = 900.0) -> list[str]:
        name = hostname.lower().rstrip(".")
        with self._lock:
            cached = self._by_name.get(name)
            if cached and not cached.expired:
                self.hits += 1
                return list(cached.addresses)
        try:
            infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, OSError, UnicodeError):
            return []
        addresses = sorted({info[4][0] for info in infos if info[4]})
        entry = ResolvedName(name, addresses, ttl, "system resolver", time.time())
        with self._lock:
            self.queries += 1
            self._by_name[name] = entry
            for addr in addresses:
                self._by_ip[addr] = entry
            self._evict()
        return addresses

    def reverse(self, ip: str, ttl: float = 3600.0, timeout: float = 1.5) -> str | None:
        """Reverse DNS with a hard timeout.

        ``socket.gethostbyaddr`` has no timeout of its own on Windows and can
        block for many seconds on an address nobody answers for, so the lookup
        runs in a helper thread that is abandoned if it takes too long.
        """
        with self._lock:
            cached = self._by_ip.get(ip)
            if cached and not cached.expired:
                self.hits += 1
                return cached.name or None
        result: dict[str, str | None] = {}

        def worker() -> None:
            try:
                result["name"] = socket.gethostbyaddr(ip)[0].rstrip(".")
            except (OSError, socket.error):
                result["name"] = None

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        thread.join(timeout)
        if thread.is_alive() or not result.get("name"):
            with self._lock:
                self._by_ip[ip] = ResolvedName("", [], 300.0, "reverse DNS (no answer)", time.time())
                self.queries += 1
            return None
        name = result["name"]
        if not name or name == ip:
            return None
        entry = ResolvedName(name, [ip], ttl, "reverse DNS", time.time())
        with self._lock:
            self.queries += 1
            self._by_ip[ip] = entry
            self._by_name.setdefault(name.lower(), entry)
        return name

    def known_domain(self, ip: str) -> str | None:
        with self._lock:
            entry = self._by_ip.get(ip)
            if entry and not entry.expired:
                return entry.name
        return None

    def register_answer(self, query_name: str, addresses: list[str], ttl: float = 300.0,
                        source: str = "observed DNS") -> None:
        """Record a real DNS answer seen on the wire or reported by an agent."""
        name = query_name.lower().rstrip(".")
        entry = ResolvedName(name, list(addresses), ttl, source, time.time())
        with self._lock:
            self._by_name[name] = entry
            for addr in addresses:
                self._by_ip[addr] = entry

    def stats(self) -> dict:
        return {"cache_size": len(self._by_ip), "queries": self.queries, "hits": self.hits}


def decode_dns_packet(payload: bytes) -> list[dict]:
    """Decode a DNS message.  Returns a list of question records (may be empty)."""
    if not HAS_DNSPYTHON or not payload:
        return []
    try:
        message = dns.message.from_wire(payload)
    except Exception:
        return []
    records: list[dict] = []
    answers: list[str] = []
    for rrset in message.answer:
        try:
            if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                for item in rrset:
                    answers.append(str(item))
        except Exception:
            continue
    ttl = 300
    for rrset in message.answer:
        ttl = min(ttl, rrset.ttl)
    for question in message.question:
        records.append(
            {
                "domain": str(question.name).rstrip("."),
                "qtype": dns.rdatatype.to_text(question.rdtype),
                "answers": answers,
                "ttl": ttl,
            }
        )
    return records


class DnsMonitorService:
    """Stores observed DNS queries and answers, and answers enrichment queries."""

    def __init__(self, db, resolver: DnsResolver, settings) -> None:
        self.db = db
        self.resolver = resolver
        self.settings = settings
        self._buffer: list[tuple] = []
        self._lock = threading.Lock()
        self.captured_queries = 0
        self.captured_encrypted = 0

    # -- ingestion -------------------------------------------------------
    def record(self, domain: str, client_ip: str | None, qtype: str = "A",
               answers: list[str] | None = None, source: str = "passive capture",
               device_id: int | None = None, server: str | None = None) -> None:
        from networksentinel.core.util import now_ts

        domain = (domain or "").strip().rstrip(".")
        if not domain or is_local_name(domain):
            return
        answers = answers or []
        if answers:
            self.resolver.register_answer(domain, answers, source=source)
        ts = now_ts()
        category = categorize(domain)
        with self._lock:
            self._buffer.append(
                (ts, device_id, client_ip, domain, qtype, server, ",".join(answers[:8]),
                 source, category)
            )
            self.captured_queries += 1
        if self.settings.get("store_dns", True) and len(self._buffer) >= 25:
            self.flush()

    def flush(self) -> int:
        with self._lock:
            rows = self._buffer
            self._buffer = []
        if not rows:
            return 0
        self.db.executemany(
            "INSERT INTO dns_queries(ts, device_id, client_ip, domain, qtype, server, "
            "answer, source, category) VALUES(?,?,?,?,?,?,?,?,?)",
            rows,
        )
        return len(rows)

    # -- reporting -------------------------------------------------------
    def domains(self, since: float = 0.0, device_id: int | None = None,
                category: str | None = None, search: str | None = None,
                limit: int = 500) -> list[dict]:
        sql = [
            "SELECT domain, MAX(category) AS category, COUNT(*) AS queries,",
            "MIN(ts) AS first_seen, MAX(ts) AS last_seen,",
            "COUNT(DISTINCT device_id) AS devices, GROUP_CONCAT(DISTINCT client_ip) AS clients",
            "FROM dns_queries WHERE ts >= ?",
        ]
        params: list = [since]
        if device_id:
            sql.append("AND device_id = ?")
            params.append(device_id)
        if category:
            sql.append("AND category = ?")
            params.append(category)
        if search:
            sql.append("AND domain LIKE ?")
            params.append(f"%{search}%")
        sql.append("GROUP BY domain ORDER BY queries DESC LIMIT ?")
        params.append(limit)
        rows = self.db.query(" ".join(sql), params)
        out = []
        for row in rows:
            data = dict(row)
            data["category"] = data.get("category") or categorize(data["domain"])
            out.append(data)
        return out

    def recent(self, limit: int = 200) -> list[dict]:
        rows = self.db.query(
            "SELECT * FROM dns_queries ORDER BY ts DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in rows]

    def counts_by_category(self, since: float) -> list[tuple[str, int]]:
        rows = self.db.query(
            "SELECT category, COUNT(*) FROM dns_queries WHERE ts >= ? "
            "GROUP BY category ORDER BY 2 DESC",
            (since,),
        )
        return [(r[0] or "Unknown destination", r[1]) for r in rows]

    def top_domains(self, since: float, limit: int = 10) -> list[dict]:
        return self.domains(since=since, limit=limit)

    def stats(self) -> dict:
        return {
            "total": self.db.scalar("SELECT COUNT(*) FROM dns_queries"),
            "today": self.db.scalar(
                "SELECT COUNT(*) FROM dns_queries WHERE ts >= ?",
                (time.time() - 86400,),
            ),
            "unique_domains": self.db.scalar("SELECT COUNT(DISTINCT domain) FROM dns_queries"),
            "captured": self.captured_queries,
            "encrypted_note": (
                "Encrypted DNS (DoH/DoT), VPN tunnels and proxies hide queries from "
                "passive observation."
            ),
        }
