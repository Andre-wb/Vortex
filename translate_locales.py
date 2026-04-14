#!/usr/bin/env python3
"""
Translate all English fallback strings in locale files to their native languages.
Uses Google Translate via deep-translator.
"""

import json
import os
import sys
import time
import re

from deep_translator import GoogleTranslator

LOCALE_DIR = 'static/locales'
BATCH_SIZE = 40  # strings per API call
SEPARATOR = '\n|||SEP|||\n'
SKIP_VALUES = {'VORTEX', '', ' '}

# Map our locale codes → Google Translate codes
CODE_MAP = {
    # Code remaps (our code → Google code)
    'he': 'iw',        # Hebrew
    'jv': 'jw',        # Javanese
    'zh': 'zh-CN',
    'zh-TW': 'zh-TW',
    'no': 'no',
    'tl': 'tl',
    'su': 'su',
    'fy': 'fy',
    'lb': 'lb',
    # Not supported by Google Translate (21 languages)
    'ab': None,        # Abkhaz
    'av': None,        # Avar
    'ba': None,        # Bashkir
    'bal': None,       # Balochi
    'bo': None,        # Tibetan
    'bua': None,       # Buryat
    'ce': None,        # Chechen
    'ckt': None,       # Chukchi
    'crh': None,       # Crimean Tatar
    'cv': None,        # Chuvash
    'ff': None,        # Fula
    'kv': None,        # Komi
    'mhr': None,       # Mari
    'oc': None,        # Occitan
    'os': None,        # Ossetian
    'sah': None,       # Yakut
    'tn': None,        # Tswana
    'tok': None,       # Toki Pona
    'tyv': None,       # Tuvan
    'udm': None,       # Udmurt
    'wo': None,        # Wolof
    # Other unsupported
    'kbd': None, 'ady': None, 'inh': None, 'lez': None,
    'alt': None, 'mrj': None, 'myv': None, 'mdf': None,
    'sjd': None, 'nah': None, 'ts': None, 'dz': None,
    'sc': None, 'br': None, 'se': None, 'smn': None,
    'li': None, 'fo': None, 'hsb': None, 'dsb': None,
}

def get_google_code(locale_code):
    """Map our locale code to Google Translate code. Returns None if unsupported."""
    if locale_code in CODE_MAP:
        return CODE_MAP[locale_code]
    # Check if Google supports this code directly
    try:
        supported = GoogleTranslator.get_supported_languages(as_dict=True)
        if locale_code in supported.values():
            return locale_code
        # Try matching by checking
        return locale_code
    except:
        return locale_code


def collect_fallback_strings(en_data, locale_data):
    """Find all keys where locale value == en value (fallback)."""
    fallbacks = []  # list of (section, key, en_value)
    for section, keys in en_data.items():
        if isinstance(keys, dict):
            for k, v in keys.items():
                if isinstance(v, str) and v and locale_data.get(section, {}).get(k) == v:
                    if v not in SKIP_VALUES:
                        fallbacks.append((section, k, v))
        elif isinstance(keys, list):
            loc_list = locale_data.get(section, [])
            if isinstance(loc_list, list) and loc_list == keys:
                for i, v in enumerate(keys):
                    if isinstance(v, str) and v:
                        fallbacks.append((section, f'__arr_{i}', v))
    return fallbacks


def batch_translate(strings, target_lang, retries=3):
    """Translate a batch of strings by joining with separator."""
    if not strings:
        return strings

    text = SEPARATOR.join(strings)
    for attempt in range(retries):
        try:
            translator = GoogleTranslator(source='en', target=target_lang)
            result = translator.translate(text)
            if not result:
                return strings  # fallback to original

            parts = result.split('|||SEP|||')
            # Clean up parts
            parts = [p.strip() for p in parts]

            if len(parts) != len(strings):
                # Separator got mangled, try one by one
                return translate_one_by_one(strings, target_lang)

            # Restore placeholders that might have been translated
            restored = []
            for orig, translated in zip(strings, parts):
                # Restore {placeholders}
                orig_placeholders = re.findall(r'\{[^}]+\}', orig)
                trans_placeholders = re.findall(r'\{[^}]+\}', translated)
                if len(orig_placeholders) != len(trans_placeholders):
                    # Placeholders got mangled, try to fix
                    for ph in orig_placeholders:
                        if ph not in translated:
                            # placeholder was translated, try to find and restore
                            translated = translated  # keep as is, best effort
                restored.append(translated)
            return restored

        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
            else:
                print(f'    ERROR translating batch: {e}')
                return strings  # fallback to original


def translate_one_by_one(strings, target_lang):
    """Fallback: translate strings individually."""
    results = []
    translator = GoogleTranslator(source='en', target=target_lang)
    for s in strings:
        try:
            r = translator.translate(s)
            results.append(r if r else s)
            time.sleep(0.1)
        except:
            results.append(s)
    return results


def process_locale(fname, en_data):
    """Process a single locale file."""
    locale_code = fname.replace('.json', '')
    google_code = get_google_code(locale_code)

    if google_code is None:
        print(f'  SKIP {fname} — language not supported by Google Translate', flush=True)
        return 0

    path = os.path.join(LOCALE_DIR, fname)
    locale_data = json.load(open(path, encoding='utf-8'))

    fallbacks = collect_fallback_strings(en_data, locale_data)
    if not fallbacks:
        print(f'  {fname}: no fallbacks to translate', flush=True)
        return 0

    print(f'  {fname}: {len(fallbacks)} fallback strings → translating to {google_code}...', flush=True)

    # Extract just the strings
    strings = [f[2] for f in fallbacks]

    # Translate in batches
    translated = []
    for i in range(0, len(strings), BATCH_SIZE):
        batch = strings[i:i + BATCH_SIZE]
        result = batch_translate(batch, google_code)
        translated.extend(result)
        if i + BATCH_SIZE < len(strings):
            time.sleep(0.3)  # rate limit

    # Apply translations
    changed = 0
    for (section, key, orig), trans in zip(fallbacks, translated):
        if trans and trans != orig:
            if key.startswith('__arr_'):
                idx = int(key.replace('__arr_', ''))
                if isinstance(locale_data.get(section), list) and idx < len(locale_data[section]):
                    locale_data[section][idx] = trans
                    changed += 1
            else:
                if section in locale_data and isinstance(locale_data[section], dict):
                    locale_data[section][key] = trans
                    changed += 1

    if changed > 0:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(locale_data, f, ensure_ascii=False, indent=2)
            f.write('\n')

    print(f'  {fname}: {changed}/{len(fallbacks)} strings translated', flush=True)
    return changed


def main():
    en_data = json.load(open(os.path.join(LOCALE_DIR, 'en.json'), encoding='utf-8'))

    # Priority order: most common languages first
    priority = [
        'ru', 'es', 'de', 'fr', 'zh', 'ja', 'ko',
        'pt', 'it', 'ar', 'hi', 'tr', 'pl', 'nl',
        'uk', 'id', 'th', 'vi', 'sv', 'da', 'fi',
        'no', 'cs', 'ro', 'hu', 'el', 'he', 'fa',
        'bg', 'hr', 'sr', 'sk', 'sl', 'lt', 'lv',
        'et', 'ka', 'hy', 'az', 'kk', 'uz', 'tg',
        'ky', 'tk', 'mn', 'ms', 'tl', 'sw', 'am',
        'yo', 'ig', 'ha', 'zu', 'xh', 'af', 'sq',
        'mk', 'bs', 'mt', 'is', 'ga', 'cy', 'gd',
        'eu', 'ca', 'gl', 'la', 'eo', 'bn', 'ta',
        'te', 'ml', 'kn', 'mr', 'gu', 'pa', 'si',
        'ne', 'my', 'km', 'lo', 'ur', 'ps', 'ku',
        'sd', 'ug', 'so', 'mg', 'rw', 'ny', 'sn',
        'st', 'tn', 'wo', 'om', 'ti', 'be', 'tt',
        'ba', 'mi', 'haw', 'sm', 'to', 'fj', 'jv', 'su',
        'zh-TW',
    ]

    # Add any remaining files not in priority list
    all_files = [f.replace('.json', '') for f in os.listdir(LOCALE_DIR)
                 if f.endswith('.json') and f != 'en.json']
    for code in all_files:
        if code not in priority:
            priority.append(code)

    total_changed = 0
    total_files = 0

    for code in priority:
        fname = code + '.json'
        if not os.path.exists(os.path.join(LOCALE_DIR, fname)):
            continue
        try:
            changed = process_locale(fname, en_data)
            total_changed += changed
            total_files += 1
        except Exception as e:
            print(f'  ERROR processing {fname}: {e}')

    print(f'\nDONE: {total_changed} strings translated across {total_files} files')


if __name__ == '__main__':
    main()
