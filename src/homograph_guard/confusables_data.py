"""Curated confusable-character table (generated; Unicode names verified at build time).

Maps a single code point to the ASCII "prototype" it is visually confused with.
Sources: Unicode TR39 confusables plus look-alikes observed in real phishing kits.
Load the full official table at runtime with --confusables PATH (confusables.txt).
"""

CURATED: dict[str, str] = {
    # -> 'a'
    "\u0430": 'a',  # CYRILLIC SMALL LETTER A
    "\u0251": 'a',  # LATIN SMALL LETTER ALPHA
    "\u03b1": 'a',  # GREEK SMALL LETTER ALPHA
    "\u1d00": 'a',  # LATIN LETTER SMALL CAPITAL A
    # -> 'b'
    "\u0185": 'b',  # LATIN SMALL LETTER TONE SIX
    "\u044c": 'b',  # CYRILLIC SMALL LETTER SOFT SIGN
    "\u1472": 'b',  # CANADIAN SYLLABICS KA
    "\u13cf": 'b',  # CHEROKEE LETTER SI
    "\u13f4": 'b',  # CHEROKEE LETTER YV
    # -> 'c'
    "\u0441": 'c',  # CYRILLIC SMALL LETTER ES
    "\u03f2": 'c',  # GREEK LUNATE SIGMA SYMBOL
    "\u1d04": 'c',  # LATIN LETTER SMALL CAPITAL C
    "\u2ca5": 'c',  # COPTIC SMALL LETTER SIMA
    "\u13df": 'c',  # CHEROKEE LETTER TLI
    "\u217d": 'c',  # SMALL ROMAN NUMERAL ONE HUNDRED
    # -> 'd'
    "\u0501": 'd',  # CYRILLIC SMALL LETTER KOMI DE
    "\u146f": 'd',  # CANADIAN SYLLABICS KO
    "\u13a0": 'd',  # CHEROKEE LETTER A
    "\u217e": 'd',  # SMALL ROMAN NUMERAL FIVE HUNDRED
    # -> 'e'
    "\u0435": 'e',  # CYRILLIC SMALL LETTER IE
    "\u04bd": 'e',  # CYRILLIC SMALL LETTER ABKHASIAN CHE
    "\uab32": 'e',  # LATIN SMALL LETTER BLACKLETTER E
    "\u13ac": 'e',  # CHEROKEE LETTER GV
    "\u212f": 'e',  # SCRIPT SMALL E
    # -> 'f'
    "\u0192": 'f',  # LATIN SMALL LETTER F WITH HOOK
    "\ua799": 'f',  # LATIN SMALL LETTER F WITH STROKE
    "\u1e9d": 'f',  # LATIN SMALL LETTER LONG S WITH HIGH STROKE
    # -> 'g'
    "\u0261": 'g',  # LATIN SMALL LETTER SCRIPT G
    "\u0581": 'g',  # ARMENIAN SMALL LETTER CO
    "\u018d": 'g',  # LATIN SMALL LETTER TURNED DELTA
    "\u1d83": 'g',  # LATIN SMALL LETTER G WITH PALATAL HOOK
    "\u13c0": 'g',  # CHEROKEE LETTER NAH
    # -> 'h'
    "\u04bb": 'h',  # CYRILLIC SMALL LETTER SHHA
    "\u0570": 'h',  # ARMENIAN SMALL LETTER HO
    "\u13bb": 'h',  # CHEROKEE LETTER MI
    "\u210e": 'h',  # PLANCK CONSTANT
    # -> 'i'
    "\u0456": 'i',  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "\u0131": 'i',  # LATIN SMALL LETTER DOTLESS I
    "\u0269": 'i',  # LATIN SMALL LETTER IOTA
    "\u03b9": 'i',  # GREEK SMALL LETTER IOTA
    "\u2170": 'i',  # SMALL ROMAN NUMERAL ONE
    # -> 'j'
    "\u0458": 'j',  # CYRILLIC SMALL LETTER JE
    "\u03f3": 'j',  # GREEK LETTER YOT
    "\u0237": 'j',  # LATIN SMALL LETTER DOTLESS J
    "\u13ab": 'j',  # CHEROKEE LETTER GU
    # -> 'k'
    "\u03ba": 'k',  # GREEK SMALL LETTER KAPPA
    "\u043a": 'k',  # CYRILLIC SMALL LETTER KA
    "\u1d0b": 'k',  # LATIN LETTER SMALL CAPITAL K
    "\u0138": 'k',  # LATIN SMALL LETTER KRA
    "\u13e6": 'k',  # CHEROKEE LETTER TSO
    # -> 'l'
    "\u04cf": 'l',  # CYRILLIC SMALL LETTER PALOCHKA
    "\u01c0": 'l',  # LATIN LETTER DENTAL CLICK
    "\u05d5": 'l',  # HEBREW LETTER VAV
    "\u0627": 'l',  # ARABIC LETTER ALEF
    "\u0142": 'l',  # LATIN SMALL LETTER L WITH STROKE
    "\u026d": 'l',  # LATIN SMALL LETTER L WITH RETROFLEX HOOK
    "\u0140": 'l',  # LATIN SMALL LETTER L WITH MIDDLE DOT
    "\u019a": 'l',  # LATIN SMALL LETTER L WITH BAR
    "\u026b": 'l',  # LATIN SMALL LETTER L WITH MIDDLE TILDE
    "\u13de": 'l',  # CHEROKEE LETTER TLE
    "\u217c": 'l',  # SMALL ROMAN NUMERAL FIFTY
    "\u2113": 'l',  # SCRIPT SMALL L
    "\u0661": 'l',  # ARABIC-INDIC DIGIT ONE
    "\u06f1": 'l',  # EXTENDED ARABIC-INDIC DIGIT ONE
    "\u07ca": 'l',  # NKO LETTER A
    "\u2d4f": 'l',  # TIFINAGH LETTER YAN
    # -> 'm'
    "\u043c": 'm',  # CYRILLIC SMALL LETTER EM
    "\u1d0d": 'm',  # LATIN LETTER SMALL CAPITAL M
    "\u0271": 'm',  # LATIN SMALL LETTER M WITH HOOK
    "\u13b7": 'm',  # CHEROKEE LETTER LU
    "\u217f": 'm',  # SMALL ROMAN NUMERAL ONE THOUSAND
    # -> 'n'
    "\u0578": 'n',  # ARMENIAN SMALL LETTER VO
    "\u057c": 'n',  # ARMENIAN SMALL LETTER RA
    "\u0274": 'n',  # LATIN LETTER SMALL CAPITAL N
    "\u03b7": 'n',  # GREEK SMALL LETTER ETA
    "\u043f": 'n',  # CYRILLIC SMALL LETTER PE
    "\u0273": 'n',  # LATIN SMALL LETTER N WITH RETROFLEX HOOK
    # -> 'o'
    "\u043e": 'o',  # CYRILLIC SMALL LETTER O
    "\u03bf": 'o',  # GREEK SMALL LETTER OMICRON
    "\u0585": 'o',  # ARMENIAN SMALL LETTER OH
    "\u03c3": 'o',  # GREEK SMALL LETTER SIGMA
    "\u1d0f": 'o',  # LATIN LETTER SMALL CAPITAL O
    "\u04e9": 'o',  # CYRILLIC SMALL LETTER BARRED O
    "\u00f8": 'o',  # LATIN SMALL LETTER O WITH STROKE
    "\u0275": 'o',  # LATIN SMALL LETTER BARRED O
    "\u0d20": 'o',  # MALAYALAM LETTER TTHA
    "\u0c66": 'o',  # TELUGU DIGIT ZERO
    "\u0ce6": 'o',  # KANNADA DIGIT ZERO
    "\u0966": 'o',  # DEVANAGARI DIGIT ZERO
    "\u0ae6": 'o',  # GUJARATI DIGIT ZERO
    "\u0be6": 'o',  # TAMIL DIGIT ZERO
    "\u0e50": 'o',  # THAI DIGIT ZERO
    "\u0ed0": 'o',  # LAO DIGIT ZERO
    "\u1040": 'o',  # MYANMAR DIGIT ZERO
    "\u0665": 'o',  # ARABIC-INDIC DIGIT FIVE
    "\u0b66": 'o',  # ORIYA DIGIT ZERO
    "\u09e6": 'o',  # BENGALI DIGIT ZERO
    "\u0a66": 'o',  # GURMUKHI DIGIT ZERO
    "\u0d66": 'o',  # MALAYALAM DIGIT ZERO
    "\u101d": 'o',  # MYANMAR LETTER WA
    "\u05e1": 'o',  # HEBREW LETTER SAMEKH
    "\u0647": 'o',  # ARABIC LETTER HEH
    "\u0b20": 'o',  # ORIYA LETTER TTHA
    # -> 'p'
    "\u0440": 'p',  # CYRILLIC SMALL LETTER ER
    "\u03c1": 'p',  # GREEK SMALL LETTER RHO
    "\u03f1": 'p',  # GREEK RHO SYMBOL
    "\u1d18": 'p',  # LATIN LETTER SMALL CAPITAL P
    "\u13e2": 'p',  # CHEROKEE LETTER TLV
    "\u2ca3": 'p',  # COPTIC SMALL LETTER RO
    # -> 'q'
    "\u051b": 'q',  # CYRILLIC SMALL LETTER QA
    "\u0563": 'q',  # ARMENIAN SMALL LETTER GIM
    "\u0566": 'q',  # ARMENIAN SMALL LETTER ZA
    # -> 'r'
    "\u0433": 'r',  # CYRILLIC SMALL LETTER GHE
    "\u1d26": 'r',  # GREEK LETTER SMALL CAPITAL GAMMA
    "\u027e": 'r',  # LATIN SMALL LETTER R WITH FISHHOOK
    "\u13a1": 'r',  # CHEROKEE LETTER E
    "\u0280": 'r',  # LATIN LETTER SMALL CAPITAL R
    # -> 's'
    "\u0455": 's',  # CYRILLIC SMALL LETTER DZE
    "\ua731": 's',  # LATIN LETTER SMALL CAPITAL S
    "\u0282": 's',  # LATIN SMALL LETTER S WITH HOOK
    "\u13da": 's',  # CHEROKEE LETTER DU
    # -> 't'
    "\u03c4": 't',  # GREEK SMALL LETTER TAU
    "\u0442": 't',  # CYRILLIC SMALL LETTER TE
    "\u1d1b": 't',  # LATIN LETTER SMALL CAPITAL T
    "\u01ab": 't',  # LATIN SMALL LETTER T WITH PALATAL HOOK
    "\u13a2": 't',  # CHEROKEE LETTER I
    # -> 'u'
    "\u057d": 'u',  # ARMENIAN SMALL LETTER SEH
    "\u03c5": 'u',  # GREEK SMALL LETTER UPSILON
    "\u1d1c": 'u',  # LATIN LETTER SMALL CAPITAL U
    "\u028b": 'u',  # LATIN SMALL LETTER V WITH HOOK
    "\ua79f": 'u',  # LATIN SMALL LETTER VOLAPUK UE
    # -> 'v'
    "\u03bd": 'v',  # GREEK SMALL LETTER NU
    "\u0475": 'v',  # CYRILLIC SMALL LETTER IZHITSA
    "\u1d20": 'v',  # LATIN LETTER SMALL CAPITAL V
    "\u13d9": 'v',  # CHEROKEE LETTER DO
    "\u2174": 'v',  # SMALL ROMAN NUMERAL FIVE
    # -> 'w'
    "\u051d": 'w',  # CYRILLIC SMALL LETTER WE
    "\u0461": 'w',  # CYRILLIC SMALL LETTER OMEGA
    "\u1d21": 'w',  # LATIN LETTER SMALL CAPITAL W
    "\u03c9": 'w',  # GREEK SMALL LETTER OMEGA
    "\u0561": 'w',  # ARMENIAN SMALL LETTER AYB
    "\u026f": 'w',  # LATIN SMALL LETTER TURNED M
    "\u13b3": 'w',  # CHEROKEE LETTER LA
    "\u13d4": 'w',  # CHEROKEE LETTER TA
    # -> 'x'
    "\u0445": 'x',  # CYRILLIC SMALL LETTER HA
    "\u03c7": 'x',  # GREEK SMALL LETTER CHI
    "\u2179": 'x',  # SMALL ROMAN NUMERAL TEN
    "\u1541": 'x',  # CANADIAN SYLLABICS SAYISI YI
    # -> 'y'
    "\u0443": 'y',  # CYRILLIC SMALL LETTER U
    "\u04af": 'y',  # CYRILLIC SMALL LETTER STRAIGHT U
    "\u03b3": 'y',  # GREEK SMALL LETTER GAMMA
    "\u0263": 'y',  # LATIN SMALL LETTER GAMMA
    "\u028f": 'y',  # LATIN LETTER SMALL CAPITAL Y
    "\u10e7": 'y',  # GEORGIAN LETTER QAR
    "\u13bd": 'y',  # CHEROKEE LETTER MU
    "\u1eff": 'y',  # LATIN SMALL LETTER Y WITH LOOP
    # -> 'z'
    "\u1d22": 'z',  # LATIN LETTER SMALL CAPITAL Z
    "\u01b6": 'z',  # LATIN SMALL LETTER Z WITH STROKE
    "\u0290": 'z',  # LATIN SMALL LETTER Z WITH RETROFLEX HOOK
    "\u0225": 'z',  # LATIN SMALL LETTER Z WITH HOOK
    "\u13c3": 'z',  # CHEROKEE LETTER NO
    # -> '2'
    "\u01bb": '2',  # LATIN LETTER TWO WITH STROKE
    # -> '3'
    "\u0437": '3',  # CYRILLIC SMALL LETTER ZE
    "\u0292": '3',  # LATIN SMALL LETTER EZH
    "\u021d": '3',  # LATIN SMALL LETTER YOGH
    "\u04e1": '3',  # CYRILLIC SMALL LETTER ABKHASIAN DZE
    # -> '5'
    "\u01bd": '5',  # LATIN SMALL LETTER TONE FIVE
    # -> '6'
    "\u0431": '6',  # CYRILLIC SMALL LETTER BE
    # -> '8'
    "\u0223": '8',  # LATIN SMALL LETTER OU
    "\u09ea": '8',  # BENGALI DIGIT FOUR
    "\u0a6a": '8',  # GURMUKHI DIGIT FOUR
    # -> '9'
    "\u09ed": '9',  # BENGALI DIGIT SEVEN
    "\u0a67": '9',  # GURMUKHI DIGIT ONE
    "\u0b68": '9',  # ORIYA DIGIT TWO
    # -> '-'
    "\u30fc": '-',  # KATAKANA-HIRAGANA PROLONGED SOUND MARK
    "\u4e00": '-',  # CJK UNIFIED IDEOGRAPH-4E00
    "\u2010": '-',  # HYPHEN
    "\u2011": '-',  # NON-BREAKING HYPHEN
    "\u2012": '-',  # FIGURE DASH
    "\u2013": '-',  # EN DASH
    "\u2014": '-',  # EM DASH
    "\u2015": '-',  # HORIZONTAL BAR
    "\u2212": '-',  # MINUS SIGN
    "\u2043": '-',  # HYPHEN BULLET
    "\u02d7": '-',  # MODIFIER LETTER MINUS SIGN
    "\u1173": '-',  # HANGUL JUNGSEONG EU
    "\u3161": '-',  # HANGUL LETTER EU
    "\u2e3a": '-',  # TWO-EM DASH
    # -> '.'
    "\u00b7": '.',  # MIDDLE DOT
    "\u0589": '.',  # ARMENIAN FULL STOP
    "\u30fb": '.',  # KATAKANA MIDDLE DOT
    "\u0701": '.',  # SYRIAC SUPRALINEAR FULL STOP
    "\u0702": '.',  # SYRIAC SUBLINEAR FULL STOP
    "\ua60e": '.',  # VAI FULL STOP
    "\u2024": '.',  # ONE DOT LEADER
    "\u0660": '.',  # ARABIC-INDIC DIGIT ZERO
    "\u06f0": '.',  # EXTENDED ARABIC-INDIC DIGIT ZERO
    "\uff65": '.',  # HALFWIDTH KATAKANA MIDDLE DOT
    "\u2027": '.',  # HYPHENATION POINT
    # -> '/'
    "\u2215": '/',  # DIVISION SLASH
    "\u2044": '/',  # FRACTION SLASH
    "\u29f8": '/',  # BIG SOLIDUS
    "\u2571": '/',  # BOX DRAWINGS LIGHT DIAGONAL UPPER RIGHT TO LOWER LEFT
    "\uff0f": '/',  # FULLWIDTH SOLIDUS
    "\u30ce": '/',  # KATAKANA LETTER NO
    "\u4e3f": '/',  # CJK UNIFIED IDEOGRAPH-4E3F
    "\u2f03": '/',  # KANGXI RADICAL SLASH
}
