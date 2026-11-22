#!/usr/bin/env python3
import argparse
import json
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BLOCK_STATUSES = {403, 406, 409, 419, 429, 501}
WAF_MARKERS = [
    "cloudflare", "modsecurity", "mod_security", "akamai", "imperva",
    "incapsula", "sucuri", "aws waf", "attention required", "request blocked",
    "access denied", "web application firewall", "f5 networks", "barracuda",
    "fortiweb", "blocked by", "security policy",
]
WAF_HEADERS = [
    ("cf-ray", "Cloudflare"), ("cf-cache-status", "Cloudflare"),
    ("x-sucuri-id", "Sucuri"), ("x-sucuri-cache", "Sucuri"),
    ("x-cdn", "CDN/WAF"), ("x-akamai", "Akamai"),
    ("x-incap", "Imperva Incapsula"), ("server", None),
]
ERROR_SIGNATURES = [
    ("jinja2", "Jinja2"), ("templatesyntaxerror", "Jinja2"),
    ("freemarker", "FreeMarker"), ("twig", "Twig"),
    ("smarty", "Smarty"), ("velocity", "Velocity"),
    ("mako", "Mako"), ("pebble", "Pebble"),
    ("thymeleaf", "Thymeleaf"), ("ognl", "OGNL/Struts"),
    ("spEL", "Spring SpEL"), ("TemplateError", "template engine"),
    ("template syntax", "template engine"), ("ParseException", "template engine"),
]


def build_families(a, b):
    return [
        {
            "name": "Jinja2 / Twig / Pebble / Tornado",
            "probe": "{{%d*%d}}" % (a, b),
            "broken": "{{%d*}}" % a,
            "string_probe": "{{%d*'%d'}}" % (a, a),
            "string_expect": {
                str(a * a): "Twig / Pebble (numeric string multiply)",
                str(a) * a: "Jinja2 / Mako (Python-style string multiply)",
            },
        },
        {
            "name": "FreeMarker / Velocity / Thymeleaf / SpEL",
            "probe": "${%d*%d}" % (a, b),
            "broken": "${%d*}" % a,
            "string_probe": "${%d*'%d'}" % (a, a),
            "string_expect": {
                str(a) * a: "Mako (Python-style string multiply)",
            },
        },
        {
            "name": "JSF / EL",
            "probe": "#{%d*%d}" % (a, b),
            "broken": "#{%d*}" % a,
            "string_probe": None,
            "string_expect": {},
        },
        {
            "name": "ERB",
            "probe": "<%%=%d*%d%%>" % (a, b),
            "broken": "<%%=%d*%%>" % a,
            "string_probe": None,
            "string_expect": {},
        },
        {
            "name": "Smarty",
            "probe": "{$%d*%d}" % (a, b),
            "broken": "{$%d*}" % a,
            "string_probe": None,
            "string_expect": {},
        },
    ]


def variants_for(payload, level):
    pct = urllib.parse.quote(payload, safe="")
    variants = [("raw", payload)]
    if level >= 2:
        variants.append(("url-encoded", pct))
        variants.append(("tab-whitespace", payload.replace("*", "%09*%09") if "*" in payload else payload))
        padded = payload.replace("*", "%20*%20").replace("{{", "{{%20").replace("}}", "%20}}").replace("${", "${%20").replace("#{", "#{%20")
        if padded.endswith("}") and "%20}}" not in padded:
            padded = padded[:-1] + "%20}"
        variants.append(("padded", padded))
    if level >= 3:
        variants.append(("double-encoded", urllib.parse.quote(pct, safe="")))
        variants.append(("newline-whitespace", payload.replace("*", "%0a*%0a") if "*" in payload else payload))
        variants.append(("half-encoded", payload.replace("{", "%7B", 1)))
    return variants


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body


class HttpClient:
    def __init__(self, headers, cookie, timeout):
        self.timeout = timeout
        self.base_headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        for h in headers or []:
            if ":" in h:
                k, v = h.split(":", 1)
                self.base_headers[k.strip()] = v.strip()
        if cookie:
            self.base_headers["Cookie"] = cookie
        self.opener = urllib.request.build_opener()

    def fetch(self, url, data=None):
        req = urllib.request.Request(url, data=data, headers=self.base_headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(262144)
                return Response(resp.status, dict(resp.headers), raw.decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            raw = e.read(262144)
            return Response(e.code, dict(e.headers or {}), raw.decode("utf-8", "replace"))
        except Exception as e:
            return Response(0, {}, "NETWORK_ERROR: %s" % e)


def detect_waf(resp, baseline_status):
    found = []
    lower_headers = {k.lower(): v for k, v in resp.headers.items()}
    for key, label in WAF_HEADERS:
        if key in lower_headers:
            if label:
                found.append(label)
            elif "cloudflare" in lower_headers[key].lower():
                found.append("Cloudflare")
            elif "akamai" in lower_headers[key].lower():
                found.append("Akamai")
    body_low = resp.body.lower()
    marker_hit = any(m in body_low for m in WAF_MARKERS)
    blocked = (resp.status in BLOCK_STATUSES and resp.status != baseline_status) or (marker_hit and resp.status in BLOCK_STATUSES)
    return found, blocked, marker_hit


class Target:
    def __init__(self, url, data_str):
        parsed = urllib.parse.urlparse(url)
        self.scheme = parsed.scheme
        self.netloc = parsed.netloc
        self.path = parsed.path or "/"
        self.query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        self.fragment = parsed.fragment
        self.post = urllib.parse.parse_qsl(data_str, keep_blank_values=True) if data_str else None

    def build(self, target_name, payload, pollution=False):
        def render(pairs, encode_target):
            parts = []
            for name, value in pairs:
                if name == target_name:
                    if pollution:
                        parts.append(urllib.parse.quote(name) + "=" + urllib.parse.quote(value))
                    parts.append(urllib.parse.quote(name) + "=" + (payload if encode_target else urllib.parse.quote(payload)))
                else:
                    parts.append(urllib.parse.quote(name) + "=" + urllib.parse.quote(value))
            return "&".join(parts)

        if self.post is not None:
            get_q = urllib.parse.urlencode(self.query)
            body = render(self.post, True)
            url = urllib.parse.urlunparse((self.scheme, self.netloc, self.path, "", get_q, self.fragment))
            return url, body.encode()
        q = render(self.query, True)
        url = urllib.parse.urlunparse((self.scheme, self.netloc, self.path, "", q, self.fragment))
        return url, None

    def params(self):
        if self.post is not None:
            return [n for n, _ in self.post]
        return [n for n, _ in self.query]


class Printer:
    def __init__(self, use_color):
        self.color = use_color

    def _c(self, code, text):
        return "\033[%sm%s\033[0m" % (code, text) if self.color else text

    def info(self, msg):
        print(self._c("36", "[*]") + " " + msg)

    def good(self, msg):
        print(self._c("32", "[+]") + " " + msg)

    def warn(self, msg):
        print(self._c("33", "[!]") + " " + msg)

    def bad(self, msg):
        print(self._c("31", "[!!]") + " " + msg)

    def plain(self, msg):
        print(msg)


def evaluated(resp, a, b):
    product = str(a * b)
    expr = "%d*%d" % (a, b)
    return product in resp.body and expr not in resp.body


def scan_param(client, target, name, level, delay, printer, verbose):
    result = {"param": name, "verdict": "not vulnerable", "engine": None, "evidence": [], "waf_blocked": False}
    marker = "ssti" + str(random.randint(100000, 999999)) + "x"
    url, data = target.build(name, marker)
    base = client.fetch(url, data)
    baseline_url, baseline_data = target.build(name, "baselinevalue")
    baseline = client.fetch(baseline_url, baseline_data)
    if base.status == 0:
        result["verdict"] = "unreachable"
        return result
    reflected = marker in base.body
    if verbose:
        printer.info("param %s reflected: %s (status %s)" % (name, reflected, base.status))

    a = random.randint(11, 48)
    b = random.randint(3, 9)
    families = build_families(a, b)
    any_blocked = False
    waf_names = []

    for fam in families:
        confirmed = False
        used_variant = None
        blocked_here = False
        for vname, payload in variants_for(fam["probe"], level):
            if delay:
                time.sleep(delay)
            url, data = target.build(name, payload)
            resp = client.fetch(url, data)
            names, blocked, _ = detect_waf(resp, baseline.status)
            for n in names:
                if n not in waf_names:
                    waf_names.append(n)
            if blocked:
                blocked_here = True
                any_blocked = True
                if verbose:
                    printer.warn("blocked by WAF on %s via %s (status %s)" % (fam["name"], vname, resp.status))
                continue
            if evaluated(resp, a, b):
                confirmed = True
                used_variant = vname
                break
        if not confirmed and blocked_here:
            continue
        if not confirmed:
            continue
        a2 = random.randint(51, 89)
        b2 = random.randint(3, 9)
        fam2 = [f for f in build_families(a2, b2) if f["name"] == fam["name"]][0]
        ok2 = False
        for vname, payload in variants_for(fam2["probe"], level):
            url, data = target.build(name, payload)
            resp = client.fetch(url, data)
            _, blocked, _ = detect_waf(resp, baseline.status)
            if blocked:
                continue
            if evaluated(resp, a2, b2):
                ok2 = True
                break
        if not ok2:
            continue
        engine = fam["name"]
        if fam["string_probe"]:
            for vname, payload in variants_for(fam["string_probe"], level):
                url, data = target.build(name, payload)
                resp = client.fetch(url, data)
                _, blocked, _ = detect_waf(resp, baseline.status)
                if blocked:
                    continue
                for expect, label in fam["string_expect"].items():
                    if expect in resp.body:
                        engine = label
                        break
                break
        result["verdict"] = "VULNERABLE"
        result["engine"] = engine
        result["evidence"].append("%s evaluated %d*%d=%d and %d*%d=%d via %s encoding" % (
            fam["probe"].split(str(a))[0] or fam["name"], a, b, a * b, a2, b2, a2 * b2, used_variant))
        result["waf_blocked"] = any_blocked
        result["waf_names"] = waf_names
        return result

    for fam in families:
        if delay:
            time.sleep(delay)
        url, data = target.build(name, fam["broken"])
        resp = client.fetch(url, data)
        _, blocked, _ = detect_waf(resp, baseline.status)
        if blocked:
            any_blocked = True
            continue
        body_low = resp.body.lower()
        for sig, engine_name in ERROR_SIGNATURES:
            if sig.lower() in body_low:
                result["verdict"] = "POSSIBLE (error-based)"
                result["engine"] = engine_name
                result["evidence"].append("error signature %r from malformed probe %s" % (sig, fam["broken"]))
                result["waf_blocked"] = any_blocked
                result["waf_names"] = waf_names
                return result

    if level >= 3:
        for fam in families:
            a3 = random.randint(11, 48)
            b3 = random.randint(3, 9)
            fam3 = [f for f in build_families(a3, b3) if f["name"] == fam["name"]][0]
            url, data = target.build(name, fam3["probe"], pollution=True)
            resp = client.fetch(url, data)
            _, blocked, _ = detect_waf(resp, baseline.status)
            if blocked:
                any_blocked = True
                continue
            if evaluated(resp, a3, b3):
                result["verdict"] = "VULNERABLE"
                result["engine"] = fam["name"]
                result["evidence"].append("parameter pollution bypass: %d*%d=%d" % (a3, b3, a3 * b3))
                result["waf_blocked"] = True
                result["waf_names"] = waf_names
                return result

    if any_blocked and not reflected:
        result["verdict"] = "inconclusive (WAF blocked probes)"
    elif any_blocked:
        result["verdict"] = "not confirmed (some probes WAF-blocked)"
    result["waf_blocked"] = any_blocked
    result["waf_names"] = waf_names
    return result


def main():
    parser = argparse.ArgumentParser(
        prog="ssti_tester",
        description="Server-Side Template Injection tester with WAF-aware probing. Detection only, no exploitation payloads. Test only systems you own or are authorized to test.")
    parser.add_argument("--url", required=True, help="target URL with query parameters, e.g. http://site/page?name=test")
    parser.add_argument("--param", action="append", help="parameter to test (repeatable). Default: all parameters")
    parser.add_argument("--data", help="POST form data, e.g. \"name=test&msg=hi\" (tests POST fields)")
    parser.add_argument("--header", action="append", help="extra header, e.g. \"Authorization: Bearer x\" (repeatable)")
    parser.add_argument("--cookie", help="cookie string, e.g. \"session=abc; theme=dark\"")
    parser.add_argument("--level", type=int, choices=[1, 2, 3], default=2,
                        help="1 = plain probes, 2 = + encoding/whitespace evasion, 3 = + double encoding and parameter pollution")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--delay", type=float, default=0.0, help="delay between requests in seconds")
    parser.add_argument("--report", help="write a JSON report to this path")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    printer = Printer(not args.no_color and sys.stdout.isatty())
    target = Target(args.url, args.data)
    names = args.param or target.params()
    if not names:
        printer.bad("No parameters found. Give a URL with a query string or use --data for POST fields.")
        return 2

    printer.info("Target: %s" % args.url)
    printer.info("Method: %s | Level: %d | Parameters: %s" % ("POST" if args.data else "GET", args.level, ", ".join(names)))
    client = HttpClient(args.header, args.cookie, args.timeout)

    home = client.fetch(args.url)
    waf_names, _, _ = detect_waf(home, home.status)
    if waf_names:
        printer.warn("WAF/CDN fingerprint: %s" % ", ".join(sorted(set(waf_names))))
    if home.status == 0:
        printer.bad("Target unreachable: %s" % home.body)
        return 2

    results = []
    for name in names:
        printer.info("Testing parameter: %s" % name)
        r = scan_param(client, target, name, args.level, args.delay, printer, args.verbose)
        results.append(r)
        if r["verdict"] == "VULNERABLE":
            printer.bad("VULNERABLE: %s -> %s" % (name, r["engine"]))
            for ev in r["evidence"]:
                printer.plain("    evidence: %s" % ev)
            if r.get("waf_blocked"):
                printer.warn("    note: a WAF blocked the plain probes; an evasion variant got through")
        elif r["verdict"].startswith("POSSIBLE"):
            printer.warn("POSSIBLE: %s -> %s" % (name, r["engine"]))
            for ev in r["evidence"]:
                printer.plain("    evidence: %s" % ev)
        elif "WAF" in r["verdict"] or "waf" in r["verdict"]:
            printer.warn("%s: %s" % (name, r["verdict"]))
        else:
            printer.good("%s: %s" % (name, r["verdict"]))

    printer.plain("")
    printer.info("Summary")
    vuln = [r for r in results if r["verdict"] == "VULNERABLE"]
    poss = [r for r in results if r["verdict"].startswith("POSSIBLE")]
    for r in results:
        printer.plain("  %-20s %s%s" % (r["param"], r["verdict"], (" (%s)" % r["engine"]) if r["engine"] else ""))
    if vuln:
        printer.bad("%d parameter(s) confirmed vulnerable to SSTI" % len(vuln))
    elif poss:
        printer.warn("No confirmed injection, %d possible error-based lead(s)" % len(poss))
    else:
        printer.good("No SSTI confirmed")

    if args.report:
        report = {"target": args.url, "method": "POST" if args.data else "GET", "level": args.level, "results": results}
        with open(args.report, "w") as f:
            json.dump(report, f, indent=2)
        printer.info("Report written to %s" % args.report)
    return 1 if vuln else 0


if __name__ == "__main__":
    sys.exit(main())
