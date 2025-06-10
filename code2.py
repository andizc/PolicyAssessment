#!/usr/bin/env python3
# script to find and classify companies plus locations contacted in domains.csv and nodomips.csv
import argparse, os, sys, socket, logging
import pandas as pd
import requests, whois, geoip2.database
from ipwhois import IPWhois, exceptions as ipwhois_exceptions

BAD_WORDS = ["unknown", "redacted", "domains by proxy", "markmonitor"]
WHOIS_PREF = ["org", "organization", "registrant_name", "name", "registrar"]

# logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

def wholookd(domain):
    # whois lookup
    try:
        rec = whois.whois(domain)
    except:
        return None
    # check result
    def is_valid(v):
        if not v:
            return False
        if isinstance(v, str):
            lv = v.lower().strip()
            for b in BAD_WORDS:
                if b in lv:
                    return False
        return True
    # check dict fields
    if isinstance(rec, dict):
        for k in WHOIS_PREF:
            val = rec.get(k)
            if is_valid(val):
                if isinstance(val, list):
                    return val[0]
                return val
    else:
        for a in WHOIS_PREF:
            v = getattr(rec, a, None)
            if is_valid(v):
                return v
    return None

def rdaplookd(domain, timeout=10):
    # RDAP lookup
    url = "https://rdap.org/domain/" + domain
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        data = r.json()
    except:
        return None
    # extract from vcardArray
    if data.get("vcardArray"):
        vc = data["vcardArray"]
        try:
            for f in vc[1]:
                if f[0].lower() == "org":
                    return f[3]
            for f in vc[1]:
                if f[0].lower() == "fn":
                    return f[3]
        except:
            pass
    # fallback to entities
    for ent in data.get("entities", []):
        vc = ent.get("vcardArray")
        if vc:
            try:
                for f in vc[1]:
                    if f[0].lower() == "org":
                        return f[3]
                for f in vc[1]:
                    if f[0].lower() == "fn":
                        return f[3]
            except:
                continue
    return None

def getcompd(domain):
    # get company from domain
    d = domain.lower().strip()
    if not d or d.endswith(".local") or d.endswith(".in-addr.arpa"):
        return "Unknown"
    if "amazonaws" in d:
        return "Amazon Web Services"
    # try whois
    org = wholookd(d)
    if org:
        low = org.lower().strip()
        bad = False
        for b in BAD_WORDS:
            if b in low:
                bad = True
        if not bad:
            return org
    # try rdap
    org = rdaplookd(d)
    if org:
        low = org.lower().strip()
        skip = False
        for b in BAD_WORDS:
            if b in low:
                skip = True
        if not skip:
            return org
    # strip and retry
    parts = d.split('.')
    while len(parts) > 2:
        parts.pop(0)
        nd = '.'.join(parts)
        org = wholookd(nd)
        if org and all(b not in org.lower() for b in BAD_WORDS):
            return org
        org = rdaplookd(nd)
        if org:
            return org
    # final fallback
    final = wholookd('.'.join(parts))
    if final:
        return final
    return "Unknown"

def getcomip(ip):
    # lookup via whois and rdap
    try:
        obj = IPWhois(ip)
        res = obj.lookup_whois()
        nets = res.get("nets", [])
        if nets:
            first = nets[0]
            for key in ("description", "name"):
                v = first.get(key)
                if v and isinstance(v, str):
                    lv = v.lower()
                    bad = False
                    for b in ["private", "registry", "reserved"]:
                        if b in lv:
                            bad = True
                    if not bad:
                        return v
    except:
        pass
    try:
        obj = IPWhois(ip)
        rd = obj.lookup_rdap()
        net = rd.get("network", {})
        name = net.get("name")
        if name and "private" not in name.lower():
            return name
        for e in rd.get("entities", []):
            o = rd.get("objects", {}).get(e, {})
            vc = o.get("vcardArray")
            if vc:
                try:
                    for f in vc[1]:
                        if f[0].lower() == "org":
                            return f[3]
                except:
                    pass
    except:
        pass
    return "Unknown"

def geoloci(ip, reader):
    # basic geo lookup
    try:
        r = reader.city(ip)
        code = r.country.iso_code
        if code:
            return code
    except:
        pass
    return "Unknown"

def classcom(company, first_party_name):
    # classify company
    if not company:
        return "Third Party"
    cp = company.lower().strip()
    fp = first_party_name.lower().strip()
    for b in BAD_WORDS:
        if b in cp:
            return "Unknown"
    if cp == fp or fp in cp or cp in fp:
        return "First Party"
    if "google" in cp and "analytics" not in cp and "ads" not in cp:
        return "Second Party"
    tokens = ["amazon web services", "microsoft", "azure", "cloudfront", "cloudflare", "akamai", "aws"]
    for t in tokens:
        if t in cp:
            return "Second Party"
    return "Third Party"

def main():
    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("input_dir")
    parser.add_argument("first_party_name")
    parser.add_argument("--geolite_db", default="GeoLite2-City.mmdb")
    args = parser.parse_args()
    idir = args.input_dir
    fname = args.first_party_name
    gdb = args.geolite_db
    if not os.path.isdir(idir):
        print("Input dir not found:", idir)
        sys.exit(1)
    domf = os.path.join(idir, "domains.csv")
    ipf = os.path.join(idir, "nodomips.csv")
    if not os.path.isfile(domf) or not os.path.isfile(ipf):
        print("Required file missing")
        sys.exit(1)
    if not os.path.isfile(gdb):
        print("GeoLite2 DB missing")
        sys.exit(1)
    try:
        reader = geoip2.database.Reader(gdb)
    except:
        print("Failed to load geo DB")
        sys.exit(1)
    print("Loading domains")
    df1 = pd.read_csv(domf)
    print("Loading IPs")
    df2 = pd.read_csv(ipf)
    details = []
    # process domains
    for i, row in df1.iterrows():
        dom = row["domain"]
        cont = row["queries"]
        bts = row["bytes"]
        if not dom:
            continue
        if "\n" in dom:
            dom = dom.split("\n")[0]
        org = getcompd(dom)
        party = classcom(org, fname)
        try:
            ip = socket.getaddrinfo(dom, None)[0][4][0]
            country = geoloci(ip, reader)
        except:
            country = "Unknown"
        details.append({"company": org, "party": party, "entry": dom, "entry_type": "domain", "country": country, "contacts": cont, "bytes": bts})

    # process IPs
    for i, row in df2.iterrows():
        ip = row["ip"]
        cont = row["tcp_syns"]
        bts = row["bytes"]
        if not ip:
            continue
        org = getcomip(ip)
        party = classcom(org, fname)
        country = geoloci(ip, reader)
        details.append({"company": org, "party": party, "entry": ip, "entry_type": "ip", "country": country, "contacts": cont, "bytes": bts})
    df3 = pd.DataFrame(details)
    out1 = os.path.join(idir, "company_details.csv")
    df3.to_csv(out1, index=False)
    print("Wrote details:", out1)

    # summary by company
    comp = {}
    for d in details:
        c = d["company"]
        if c not in comp:
            comp[c] = {"party": d["party"], "contacts":0, "bytes":0}
        comp[c]["contacts"] += d["contacts"]
        comp[c]["bytes"] += d["bytes"]
    rows = []
    for c, v in comp.items():
        rows.append({"company": c, "party": v["party"], "total_contacts": v["contacts"], "total_bytes": v["bytes"]})
    df4 = pd.DataFrame(rows)
    out2 = os.path.join(idir, "company_summary.csv")
    df4.to_csv(out2, index=False)
    print("Wrote summary:", out2)

    # country summary
    country_map = {}
    for d in details:
        co = d["country"]
        if co not in country_map:
            country_map[co] = {"companies": set(), "contacts":0, "bytes":0}
        country_map[co]["companies"].add(d["company"])
        country_map[co]["contacts"] += d["contacts"]
        country_map[co]["bytes"] += d["bytes"]
    rows = []
    for co, v in country_map.items():
        rows.append({"country": co, "num_companies": len(v["companies"]), "total_contacts": v["contacts"], "total_bytes": v["bytes"]})
    df5 = pd.DataFrame(rows)
    out3 = os.path.join(idir, "country_summary.csv")
    df5.to_csv(out3, index=False)
    print("Wrote country summary:", out3)

if __name__ == "__main__":
    main()
