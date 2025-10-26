#!/usr/bin/env python3
"""
pw_audit_tool.py
Defensive password-strength analyzer + custom wordlist generator.
Only use on accounts/systems you own or have explicit permission to test.
"""

import argparse
import itertools
import json
import os
import re
from datetime import datetime
from decimal import Decimal

# Patch the JSON encoder globally
def decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError

# Monkey-patch json.dumps to handle Decimal automatically
_old_dumps = json.dumps
def safe_dumps(obj, *args, **kwargs):
    kwargs['default'] = decimal_default
    return _old_dumps(obj, *args, **kwargs)
json.dumps = safe_dumps



try:
    from zxcvbn import zxcvbn
except Exception as e:
    raise SystemExit("Please install zxcvbn: pip install zxcvbn-python") from e

# Optional tkinter GUI import
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    TK_AVAILABLE = True
except Exception:
    TK_AVAILABLE = False

# ------------ Utilities ------------
COMMON_SUFFIXES = ["!", "@", "#", "123", "2020", "2021", "2022", "2023", "2024"]
COMMON_PREFIXES = ["", "!", "@", "123"]
LEET_MAP = {
    "a": ["4", "@"],
    "b": ["8"],
    "e": ["3"],
    "i": ["1", "!"],
    "l": ["1", "|"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7"]
}

def leet_variants(word, max_variants=100):
    """
    Generate leet variants by substituting some characters. Limit total results.
    Uses simple combinatorial substitution with pruning.
    """
    positions = []
    candidates = []
    for ch in word.lower():
        if ch in LEET_MAP:
            positions.append(True)
            candidates.append([ch] + LEET_MAP[ch])
        else:
            positions.append(False)
            candidates.append([ch])
    # generate combinations, but avoid explosion
    results = set()
    for combo in itertools.product(*candidates):
        results.add("".join(combo))
        if len(results) >= max_variants:
            break
    return list(results)

def case_variants(word):
    """Return common case variants: lower, upper, title, and camel-ish variants."""
    variants = {word.lower(), word.upper(), word.capitalize()}
    # simple toggle variants
    if len(word) > 1:
        variants.add(word[0].upper() + word[1:])
        variants.add(word[0].lower() + word[1:])
    return list(variants)

def append_years(words, start=1950, end=None):
    """Append year suffixes (as strings) to each word. If end None, use current year."""
    if end is None:
        end = datetime.now().year
    years = [str(y) for y in range(end, end-6, -1)]  # recent 6 years by default
    for w in list(words):
        for y in years:
            yield w + y
            yield w + y[-2:]  # 2-digit
    # also yield original words
    for w in words:
        yield w

def unique_preserve_order(seq):
    seen = set()
    out = []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out

# ------------ Wordlist generation pipeline ------------
def build_base_tokens(user_inputs):
    """
    user_inputs: dict with fields like names, dates, pets, companies, extra_words (list).
    Returns list of base tokens.
    """
    tokens = []
    for k, vals in user_inputs.items():
        if not vals:
            continue
        if isinstance(vals, str):
            tokens.extend([v.strip() for v in re.split(r"[,\n;]+", vals) if v.strip()])
        elif isinstance(vals, (list, tuple)):
            for v in vals:
                if isinstance(v, str):
                    tokens.append(v.strip())
    # clean tokens
    clean = []
    for t in tokens:
        t2 = t.strip()
        if t2:
            clean.append(re.sub(r"\s+", "", t2))  # remove internal whitespace
    return unique_preserve_order(clean)

def expand_tokens(base_tokens, max_per_base=200):
    """
    Expand with case variants, leet, suffixes, prefixes, year appenders.
    Be careful with explosion; limit per-base expansions.
    """
    out = []
    for token in base_tokens:
        variants = set()
        # case variants
        for cv in case_variants(token):
            variants.add(cv)
        # leet variants (limit)
        for lv in leet_variants(token, max_variants=40):
            variants.add(lv)
        # add suffix/prefix combos (simple)
        for v in list(variants):
            for s in COMMON_SUFFIXES:
                variants.add(v + s)
            for p in COMMON_PREFIXES:
                variants.add(p + v)
        # append recent years
        appended = list(append_years(list(variants), end=datetime.now().year))
        # limit
        for item in appended[:max_per_base]:
            out.append(item)
    # also include the base tokens themselves
    out.extend(base_tokens)
    # deduplicate and limit overall size (caller can control)
    out = unique_preserve_order(out)
    return out

# ------------ Password analysis ------------
def analyze_password(pw, user_inputs=None):
    """
    Returns zxcvbn result augmented with summary.
    user_inputs may be list of user-specific tokens to help zxcvbn detect matches.
    """
    user_inputs = user_inputs or []
    try:
        info = zxcvbn(pw, user_inputs)
    except Exception:
        # fallback minimal structure
        info = {
            "score": 0,
            "guesses": 0,
            "feedback": {"warning": "zxcvbn error", "suggestions": []},
            "sequence": []
        }
    summary = {
        "password": pw,
        "score": info.get("score"),
        "guesses": info.get("guesses_display", info.get("guesses")),
        "crack_times_display": info.get("crack_times_display", {}),
        "feedback": info.get("feedback", {}),
    }
    return summary

# ------------ Export ------------
def export_wordlist(words, filepath):
    with open(filepath, "w", encoding="utf-8") as f:
        for w in words:
            f.write(w + "\n")

# ------------ CLI ------------
def run_cli(args):
    # collect user inputs into dictionary
    user_inputs = {
        "names": args.names,
        "dates": args.dates,
        "pets": args.pets,
        "companies": args.companies,
        "extra": args.extra
    }
    base = build_base_tokens(user_inputs)
    expanded = expand_tokens(base, max_per_base=args.per_base)
    # optionally limit overall size
    if args.limit and len(expanded) > args.limit:
        expanded = expanded[:args.limit]
    # analyze sample password if provided
    analysis = None
    if args.password:
        analysis = analyze_password(args.password, user_inputs=base)
    # export
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    export_wordlist(expanded, args.output)
    print(f"Exported {len(expanded)} words to {args.output}")
    if analysis:
        print("Password analysis:")
        print(json.dumps(analysis, indent=2))

# ------------ Simple Tkinter GUI ------------
def run_gui():
    if not TK_AVAILABLE:
        raise SystemExit("tkinter is not available in this Python installation.")
    root = tk.Tk()
    root.title("Password Strength Analyzer & Wordlist Generator")

    frm = ttk.Frame(root, padding=12)
    frm.grid()

    ttk.Label(frm, text="Names (comma-separated)").grid(column=0, row=0, sticky="w")
    names = tk.StringVar()
    ttk.Entry(frm, textvariable=names, width=40).grid(column=1, row=0)

    ttk.Label(frm, text="Dates (YYYY or YYYY-MM-DD)").grid(column=0, row=1, sticky="w")
    dates = tk.StringVar()
    ttk.Entry(frm, textvariable=dates, width=40).grid(column=1, row=1)

    ttk.Label(frm, text="Pets / Extra (comma-separated)").grid(column=0, row=2, sticky="w")
    pets = tk.StringVar()
    ttk.Entry(frm, textvariable=pets, width=40).grid(column=1, row=2)

    ttk.Label(frm, text="Extra words").grid(column=0, row=3, sticky="w")
    extra = tk.StringVar()
    ttk.Entry(frm, textvariable=extra, width=40).grid(column=1, row=3)

    ttk.Label(frm, text="Password to analyze (optional)").grid(column=0, row=4, sticky="w")
    password = tk.StringVar()
    ttk.Entry(frm, textvariable=password, width=40, show="*").grid(column=1, row=4)

    ttk.Label(frm, text="Output file").grid(column=0, row=5, sticky="w")
    outpath = tk.StringVar(value="wordlist.txt")
    ttk.Entry(frm, textvariable=outpath, width=40).grid(column=1, row=5)
    def choose_file():
        p = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt")])
        if p:
            outpath.set(p)
    ttk.Button(frm, text="Browse", command=choose_file).grid(column=2, row=5)

    def on_generate():
        ui = {"names": names.get(), "dates": dates.get(), "pets": pets.get(), "extra": extra.get()}
        base = build_base_tokens(ui)
        expanded = expand_tokens(base)
        export_wordlist(expanded, outpath.get())
        msg = f"Exported {len(expanded)} words to {outpath.get()}"
        if password.get():
            analysis = analyze_password(password.get(), user_inputs=base)
            msg += "\n\nPassword analysis:\n" + json.dumps(analysis, indent=2)
        messagebox.showinfo("Done", msg)

    ttk.Button(frm, text="Generate & Analyze", command=on_generate).grid(column=1, row=6)
    root.mainloop()

# ------------ Main entrypoint ------------
def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer + Wordlist Generator (defensive use only)")
    parser.add_argument("--names", help="Comma-separated names", default="")
    parser.add_argument("--dates", help="Comma-separated dates (years or full dates)", default="")
    parser.add_argument("--pets", help="Comma-separated pet names or other tokens", default="")
    parser.add_argument("--companies", help="Comma-separated company/org names", default="")
    parser.add_argument("--extra", help="Comma-separated extra words", default="")
    parser.add_argument("--password", help="Password to analyze (optional)", default="")
    parser.add_argument("--output", help="Output .txt file", default="wordlist.txt")
    parser.add_argument("--per-base", dest="per_base", type=int, default=100, help="Max expansions per base token")
    parser.add_argument("--limit", type=int, default=0, help="Limit total number of words (0 = no limit)")
    parser.add_argument("--gui", action="store_true", help="Launch simple GUI (tkinter)")
    args = parser.parse_args()

    if args.gui:
        run_gui()
    else:
        run_cli(args)

if __name__ == "__main__":
    main()
