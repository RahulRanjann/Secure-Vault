const AMBIGUOUS = new Set("Il1O0|`'\"".split(""));

export type GeneratorOptions = {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
};

function secureIndex(max: number): number {
  if (!Number.isInteger(max) || max < 1 || max > 256) throw new Error("Invalid character set.");
  if (!globalThis.crypto?.getRandomValues) throw new Error("Secure randomness is unavailable.");
  const limit = Math.floor(256 / max) * max;
  const byte = new Uint8Array(1);
  do crypto.getRandomValues(byte); while (byte[0] >= limit);
  return byte[0] % max;
}

export function generatePassword(options: GeneratorOptions): string {
  if (!Number.isInteger(options.length) || options.length < 8 || options.length > 128) {
    throw new Error("Password length must be 8–128 characters.");
  }
  const groups = [
    options.uppercase ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "",
    options.lowercase ? "abcdefghijklmnopqrstuvwxyz" : "",
    options.digits ? "0123456789" : "",
    options.symbols ? "!@#$%^&*()-_=+[]{}:,.?" : "",
  ].filter(Boolean).map((group) => options.excludeAmbiguous ? [...group].filter((char) => !AMBIGUOUS.has(char)).join("") : group);
  if (groups.length === 0 || groups.some((group) => !group) || groups.length > options.length) {
    throw new Error("Choose at least one character type and enough length to include each selected type.");
  }
  const alphabet = [...new Set(groups.join(""))];
  if (alphabet.length > 256) throw new Error("Character set is too large.");
  const result = groups.map((group) => group[secureIndex(group.length)]);
  while (result.length < options.length) result.push(alphabet[secureIndex(alphabet.length)]);
  for (let i = result.length - 1; i > 0; i -= 1) {
    const j = secureIndex(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result.join("");
}

export function passwordStrength(password: string): "Weak" | "Fair" | "Strong" {
  let score = Math.min(4, Math.floor(password.length / 8));
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  return score < 3 ? "Weak" : score < 5 ? "Fair" : "Strong";
}