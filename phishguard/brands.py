"""Brand / keyword tables used for impersonation detection.

brand label -> set of registered domains that legitimately belong to the brand.
A URL whose *host* mentions the brand but whose registered domain is NOT in the set
is a classic phishing pattern (combo-squatting, typosquatting, subdomain spoofing).
"""

BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.in", "googleapis.com", "goo.gl", "googleusercontent.com", "gstatic.com"},
    "gmail": {"gmail.com"},
    "youtube": {"youtube.com", "youtu.be"},
    "facebook": {"facebook.com", "fb.com", "fbcdn.net"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "twitter": {"twitter.com", "t.co", "x.com"},
    "linkedin": {"linkedin.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com",
                  "outlook.com", "azure.com", "windows.com", "msn.com", "sharepoint.com"},
    "outlook": {"outlook.com", "office.com", "live.com"},
    "onedrive": {"onedrive.com", "live.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon.co.jp",
               "amzn.to", "amzn.in"},
    "netflix": {"netflix.com"},
    "spotify": {"spotify.com"},
    "ebay": {"ebay.com", "ebay.in", "ebay.co.uk"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "github": {"github.com", "githubusercontent.com", "github.io"},
    "gitlab": {"gitlab.com"},
    "zoom": {"zoom.us"},
    "telegram": {"telegram.org", "t.me"},
    "yahoo": {"yahoo.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "blockchain": {"blockchain.com"},
    "trustwallet": {"trustwallet.com"},
    "walletconnect": {"walletconnect.com", "walletconnect.org"},
    "opensea": {"opensea.io"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "usps": {"usps.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "citibank": {"citibank.com", "citi.com"},
    "hsbc": {"hsbc.com", "hsbc.co.in", "hsbc.co.uk"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "americanexpress": {"americanexpress.com", "amex.com"},
    "mastercard": {"mastercard.com"},
    # India
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
    "myntra": {"myntra.com"},
    "irctc": {"irctc.co.in"},
    "npci": {"npci.org.in"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "aadhaar": {"uidai.gov.in"},
    "airtel": {"airtel.in", "airtel.com"},
    "swiggy": {"swiggy.com"},
    "zomato": {"zomato.com"},
    "manipal": {"manipal.edu"},
}

# Short / dictionary-like brand labels: only used for exact-lookalike (typosquat) checks,
# never for plain substring matches (would fire on "snapple", "visa-requirements", ...).
AMBIGUOUS_BRANDS = {"apple", "amazon", "chase", "steam", "zoom", "kotak", "dhl", "adobe", "yahoo", "spotify",
                    "netflix", "github", "gitlab", "slack", "ebay", "visa", "meta"}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "logon", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "banking", "password", "passwd", "credential", "wallet",
    "recover", "unlock", "suspend", "limited", "billing", "invoice", "payment", "support",
    "helpdesk", "authenticate", "validate", "webscr", "alert", "locked", "reward",
    "gift", "claim", "bonus", "kyc", "otp", "airdrop", "refund", "unusual", "restore",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in", "bl.ink", "s.id", "v.gd", "t.ly",
}

# TLDs with consistently high abuse rates in public reports (Spamhaus / Interisle / Netcraft).
ABUSED_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "zip", "mov", "work", "icu", "buzz",
    "monster", "cyou", "cfd", "sbs", "rest", "fit", "support", "country", "kim", "loan", "men",
    "date", "download", "review", "party", "stream", "racing", "win", "bid", "trade", "science",
    "live", "shop", "online", "site", "website", "space", "store", "vip", "pw", "cc", "ws",
}

# Free hosting / tunnelling / dev-platform domains: legit platforms that phishing kits abuse heavily.
FREE_HOSTING_DOMAINS = {
    "firebaseapp.com", "web.app", "pages.dev", "workers.dev", "netlify.app", "vercel.app", "herokuapp.com",
    "github.io", "gitlab.io", "weebly.com", "wixsite.com", "godaddysites.com", "blogspot.com", "wordpress.com",
    "000webhostapp.com", "glitch.me", "repl.co", "replit.app", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "infura-ipfs.io", "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "mybluehost.me", "sites.google.com",
    "forms.gle", "typeform.com", "jotform.com", "square.site", "webflow.io", "framer.website", "carrd.co",
    "azurewebsites.net", "appspot.com", "r2.dev", "myshopify.com", "bubbleapps.io",
}

# Public-suffix entries with two labels (small embedded list so no network download is needed).
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "com.au", "net.au", "org.au", "edu.au",
    "gov.au", "co.in", "net.in", "org.in", "ac.in", "gov.in", "edu.in", "res.in", "firm.in", "gen.in", "ind.in",
    "nic.in", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "com.br", "net.br", "org.br", "gov.br", "com.cn",
    "net.cn", "org.cn", "gov.cn", "edu.cn", "com.mx", "com.ar", "com.co", "com.pe", "com.ve", "com.tr", "com.sg",
    "com.my", "com.hk", "com.tw", "com.ph", "com.pk", "com.bd", "com.ng", "com.eg", "com.sa", "com.ua", "com.vn",
    "co.za", "co.nz", "co.kr", "or.kr", "co.id", "co.th", "co.il", "co.ke", "co.tz", "co.ug", "org.za", "net.za",
    "gov.za", "ac.za", "com.pl", "com.ru", "com.es", "com.pt", "co.cr", "com.ec", "com.gt", "com.do", "com.np",
    "com.lk",
}
