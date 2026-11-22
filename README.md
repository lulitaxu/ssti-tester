# SSTI Tester

Server-Side Template Injection detector built for real targets: multi-engine
probing, two-stage confirmation, engine fingerprinting, and WAF-aware evasion.
Detection only. It never sends exploitation or RCE payloads.

Zero dependencies. Python 3 standard library only.

## Usage

```bash
python3 ssti_tester.py --url "http://target/page?name=test"
python3 ssti_tester.py --url "http://target/search?q=hi&page=1" --param q
python3 ssti_tester.py --url "http://target/echo" --data "msg=hello" --level 3
python3 ssti_tester.py --url "http://target/page?name=test" --cookie "session=abc" --report out.json
```

Run `python3 ssti_tester.py --help` for every option.

## How it works

1. **Reflection check.** A random marker confirms the parameter reaches the page.
2. **Math probes per engine family.** Jinja2/Twig `{{a*b}}`, FreeMarker/Velocity/
   Thymeleaf/SpEL `${a*b}`, JSF EL `#{a*b}`, ERB `<%=a*b%>`, Smarty `{$a*$b}`,
   each with fresh random operands. A hit needs the product in the response
   while the raw expression is gone.
3. **Confirmation.** A second probe with different operands must also evaluate.
   One lucky number on the page is never enough.
4. **Engine fingerprinting.** A string-multiply probe (`{{7*'7'}}`) separates
   Python-style engines (Jinja2, Mako: result `7777777`) from numeric ones
   (Twig, Pebble: result `49`).
5. **Error-based fallback.** Malformed probes look for engine error signatures
   (Jinja2, FreeMarker, Twig, Smarty, Velocity, Mako, Pebble, Thymeleaf, OGNL)
   and report a POSSIBLE lead with the engine name.

## WAF handling

Real targets sit behind Cloudflare, ModSecurity, Akamai, Sucuri and friends.
The tester fingerprints the WAF from headers and block pages, and treats a
blocked probe as blocked, never as "not vulnerable".

Evasion ladder by `--level`:

- **Level 1:** plain probes only.
- **Level 2:** + full URL encoding, tab whitespace inside expressions,
  brace/expression padding.
- **Level 3:** + double encoding, newline whitespace, half encoding, and
  parameter pollution (the payload rides a duplicated parameter).

If a WAF blocks the plain probe and an evasion variant gets through, the
report says so. If everything is blocked, the verdict is "inconclusive
(WAF blocked probes)" instead of a false clean bill.

## Verdicts

- `VULNERABLE` — two evaluated probes, engine named where fingerprinting worked.
- `POSSIBLE (error-based)` — engine error leaked, injection not confirmed.
- `not confirmed (some probes WAF-blocked)` — the WAF stopped part of the run.
- `inconclusive (WAF blocked probes)` — nothing got through.
- `not vulnerable` — all probes reflected or ignored, no evaluation.

Exit code is 1 when any parameter is confirmed vulnerable, 0 otherwise,
so it drops into scripts and CI.

## Safety

Use it only on systems you own or are authorized to test (your labs, your
clients under contract, bug bounty scope). Probing is read-only arithmetic;
nothing is written, executed or extracted on the target.
