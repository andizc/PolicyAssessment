#!/usr/bin/env python3
import argparse, os, json, csv, pandas as pd

SECCOMP = ["amazon web services", "microsoft", "azure", "cloudfront", "cloudflare", "akamai"]
GOOG_SERVS = ["analytics", "ads", "ad services"]
EXCEPTIONS = {"amazon web services", "google analytics", "google ads"}

# Party classification
def classifying(name, fp_name):
    nm = name.lower().strip()
    fp = fp_name.lower().strip()
    # first party
    if nm == fp or fp in nm or nm in fp:
        return "First Party"
    # google exceptions
    if "google" in nm:
        skip = False
        for e in GOOG_SERVS:
            if e in nm:
                skip = True
        if not skip:
            return "Second Party"
    # other second party names
    for t in SECCOMP:
        if t in nm:
            return "Second Party"
    # everything else is third p
    return "Third Party"


def main():
    # get args from terminal
    parser = argparse.ArgumentParser()
    parser.add_argument("set1_csv")
    parser.add_argument("set2_json")
    parser.add_argument("fp_name")
    parser.add_argument("output_dir")
    args = parser.parse_args()

    # make output directory if it doesnt exist
    try:
        os.makedirs(args.output_dir)
    except:
        pass

    #Number of contacts and bytes from input csv
    df1 = pd.read_csv(args.set1_csv, dtype=str).fillna("")
    if "total_contacts" in df1:
        df1["total_contacts"] = pd.to_numeric(df1["total_contacts"], errors="ignore")
    if "total_bytes" in df1:
        df1["total_bytes"] = pd.to_numeric(df1["total_bytes"], errors="ignore")
    # normalise company names
    df1["norm"] = df1["company"].str.lower().str.strip()
    # lookup dict for set1
    look1 = {}
    for idx, row in df1.iterrows():
        look1[row["norm"]] = row

    # JSON of companies from privacy policy
    try:
        with open(args.set2_json) as f:
            data = json.load(f)
    except:
        print("Could not read JSON")
        data = {}
    ment = data.get("third_parties", []) if isinstance(data.get("third_parties"), list) else []

    # classify companies from json
    set2 = []
    for comp in ment:
        nm = str(comp)
        cls = classifying(nm, args.fp_name)
        set2.append({"company": nm, "norm": nm.lower().strip(), "classification": cls})

    # write classified company file
    out1 = os.path.join(args.output_dir, "classified_companies.csv")
    try:
        with open(out1, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["company", "classification"]);
            for row in set2:
                writer.writerow([row["company"], row["classification"]])
        print("Wrote classified companies to", out1)
    except:
        print("Write error classified_companies.csv")

    # mapping between the sets
    s1_names = set(look1.keys())
    s2_names = set(r["norm"] for r in set2)
    match1 = set(); matched2 = set(); map12 = {}
    for n1 in sorted(s1_names):
        if n1 in match1: continue
        for n2 in sorted(s2_names):
            if n2 in matched2: continue
            if n1 == n2:
                map12[n1] = n2; match1.add(n1); matched2.add(n2); break
            if n1 not in EXCEPTIONS and n2 not in EXCEPTIONS and (n1 in n2 or n2 in n1):
                map12[n1] = n2; match1.add(n1); matched2.add(n2); break

    cm = match1
    cun = s1_names - match1
    unm = s2_names - matched2


    comp_rows = []
    # contacted & mentioned
    for n1 in sorted(cm):
        r1 = look1[n1]
        orig = r1["company"]
        party = r1.get("party", "")
        n2 = map12[n1]
        cls2 = next(r["classification"] for r in set2 if r["norm"] == n2)
        comp_rows.append([orig, cls2, party, r1.get("total_contacts", ""), r1.get("total_bytes", ""), r1.get("countries", ""), "contacted_and_mentioned"])
    # contacted & unmentioned
    for n1 in sorted(cun):
        r1 = look1[n1]
        orig = r1["company"]; party = r1.get("party", "")
        cls = party if party else classifying(orig, args.fp_name)
        comp_rows.append([orig, cls, party, r1.get("total_contacts", ""), r1.get("total_bytes", ""), r1.get("countries", ""), "contacted_and_unmentioned"])
    # uncontacted & mentioned
    for n2 in sorted(unm):
        cls = next(r["classification"] for r in set2 if r["norm"] == n2)
        comp_rows.append([next(r["company"] for r in set2 if r["norm"]==n2), cls, "", "", "", "", "uncontacted_and_mentioned"])

    # write comparison.csv
    out2 = os.path.join(args.output_dir, "comparison.csv")
    try:
        with open(out2, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["company","classification","original_party","total_contacts","total_bytes","countries","category"])
            for row in comp_rows:
                writer.writerow(row)
            # summary counts
            writer.writerow([])
            writer.writerow(["Category","Count"])
            writer.writerow(["contacted_and_mentioned", len(cm)])
            writer.writerow(["contacted_and_unmentioned", len(cun)])
            writer.writerow(["uncontacted_and_mentioned", len(unm)])
        print("Wrote comparison to", out2)
    except:
        print("Failed to write comparison.csv")

    # write third party comparison doc
    out3 = os.path.join(args.output_dir, "third_party_comparison.csv")
    try:
        tp_rows = [r for r in comp_rows if r[1] == "Third Party"]
        with open(out3, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["company","classification","original_party","total_contacts","total_bytes","countries","category"])
            for row in tp_rows:
                writer.writerow(row)
            # writes summary
            c_u_m = len([r for r in tp_rows if r[6]=="contacted_and_mentioned"]);
            c_u_u = len([r for r in tp_rows if r[6]=="contacted_and_unmentioned"]);
            u_u_m = len([r for r in tp_rows if r[6]=="uncontacted_and_mentioned"]);
            writer.writerow([])
            writer.writerow(["Category","Count"])
            writer.writerow(["contacted_and_mentioned", c_u_m])
            writer.writerow(["contacted_and_unmentioned", c_u_u])
            writer.writerow(["uncontacted_and_mentioned", u_u_m])
        print("Wrote third party comparison at", out3)
    except:
        print("Write error third_party_comparison.csv")

    if __name__ == "__main__":
        main()
