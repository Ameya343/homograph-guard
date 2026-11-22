// Punycode (RFC 3492) and IDN helpers. ASCII conversion uses the WHATWG URL parser,
// which is exactly what the browser itself does with a host (UTS #46 processing).

const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

function adapt(delta, numPoints, first) {
  delta = first ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((BASE - TMIN) * TMAX) >> 1) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function digitOf(cp) {
  if (cp >= 48 && cp <= 57) return cp - 22; // 0-9 -> 26-35
  if (cp >= 65 && cp <= 90) return cp - 65; // A-Z
  if (cp >= 97 && cp <= 122) return cp - 97; // a-z
  return BASE;
}

function digitChar(d) {
  return String.fromCharCode(d < 26 ? d + 97 : d + 22);
}

/** Decode the part after "xn--". Throws on malformed input. */
export function decode(input) {
  const out = [];
  let n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
  let basic = input.lastIndexOf("-");
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) throw new RangeError("not basic");
    out.push(c);
  }
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (idx >= input.length) throw new RangeError("truncated");
      const digit = digitOf(input.charCodeAt(idx++));
      if (digit >= BASE) throw new RangeError("bad digit");
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
      if (w > 0x7fffffff) throw new RangeError("overflow");
    }
    const len = out.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    if (n > 0x10ffff) throw new RangeError("overflow");
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

/** Encode a Unicode label to the part after "xn--". */
export function encode(input) {
  const cps = Array.from(input, (c) => c.codePointAt(0));
  let n = INITIAL_N, delta = 0, bias = INITIAL_BIAS;
  let out = cps.filter((c) => c < 0x80).map((c) => String.fromCharCode(c)).join("");
  const basic = out.length;
  let h = basic;
  if (basic) out += "-";
  while (h < cps.length) {
    const m = Math.min(...cps.filter((c) => c >= n));
    delta += (m - n) * (h + 1);
    n = m;
    for (const c of cps) {
      if (c < n) delta++;
      if (c === n) {
        let q = delta;
        for (let k = BASE; ; k += BASE) {
          const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
          if (q < t) break;
          out += digitChar(t + ((q - t) % (BASE - t)));
          q = Math.floor((q - t) / (BASE - t));
        }
        out += digitChar(q);
        bias = adapt(delta, h + 1, h === basic);
        delta = 0;
        h++;
      }
    }
    delta++;
    n++;
  }
  return out;
}

export function labelToUnicode(label) {
  if (!label.startsWith("xn--")) return label;
  try {
    return decode(label.slice(4));
  } catch {
    return label;
  }
}

export function hostToUnicode(host) {
  return host.split(".").map(labelToUnicode).join(".");
}

/** The ASCII host a browser would look up, or null when the browser would refuse it. */
export function browserAscii(host) {
  try {
    const h = new URL(`http://${host}/`).hostname;
    return h || null;
  } catch {
    return null;
  }
}

/** A punycode label is valid if decoding and re-encoding it through the browser is stable. */
export function validPunycodeLabel(label) {
  let u;
  try {
    u = decode(label.slice(4));
  } catch {
    return false;
  }
  if (!u || /^[\x00-\x7f]*$/.test(u)) return false;
  return browserAscii(`${u}.example`) === `${label}.example`;
}
