"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  changeMasterPassword, createQuickUnlock, createVault, exportEncryptedBackup, parseEnvelope, parseQuickUnlock, saveVault,
  resetMasterPasswordWithRecovery, unlockVault, unlockWithRecovery,
  unlockQuickVault, type QuickUnlockConfig, type QuickUnlockMethod,
} from "@/lib/crypto";
import { getDeviceUnlockSecret, registerDeviceUnlock } from "@/lib/device-unlock";
import { generatePassword, passwordStrength } from "@/lib/password-generator";
import { credentialSchema, type Credential, type CredentialType, type EncryptedVault, type LockMethod, type VaultData } from "@/lib/vault-schema";

const STORE_KEY = "secure-vault.encrypted.v1";
const QUICK_UNLOCK_KEY = "secure-vault.quick-unlock.v1";
const emptyVault: VaultData = { version: 1, credentials: [] };
type Account = { id: string; email: string; name: string };
type DriveStatus = { configured: boolean; connected: boolean };
type Dialog = "credential" | "generator" | "settings" | "recovery" | "backup" | null;
const quickUnlockLabels: Record<QuickUnlockMethod, string> = {
  device: "Device unlock",
  pin: "App PIN",
  pattern: "Unlock pattern",
  password: "App password",
};
const credentialTypeLabels: Record<CredentialType, string> = {
  login: "Login",
  "phone-lock": "Phone lock",
  "app-lock": "App lock",
};

function userVaultKey(userId: string): string {
  return `${STORE_KEY}.${userId}`;
}

function userQuickUnlockKey(userId: string): string {
  return `${QUICK_UNLOCK_KEY}.${userId}`;
}

function readLocal(userId: string): EncryptedVault | null {
  try {
    const key = userVaultKey(userId);
    let stored = localStorage.getItem(key);
    if (!stored) {
      stored = localStorage.getItem(STORE_KEY);
      if (stored) {
        localStorage.setItem(key, stored);
        localStorage.removeItem(STORE_KEY);
      }
    }
    return stored ? parseEnvelope(stored) : null;
  } catch {
    return null;
  }
}

function readQuickUnlocks(userId: string): QuickUnlockConfig[] {
  const key = userQuickUnlockKey(userId);
  let stored = localStorage.getItem(key);
  if (!stored) {
    stored = localStorage.getItem(QUICK_UNLOCK_KEY);
    if (stored) {
      localStorage.setItem(key, stored);
      localStorage.removeItem(QUICK_UNLOCK_KEY);
    }
  }
  const parsed: unknown = stored ? JSON.parse(stored) : [];
  if (!Array.isArray(parsed)) throw new Error("Quick-unlock settings must be a list.");
  return parsed.map(parseQuickUnlock);
}

export default function VaultApp() {
  const [account, setAccount] = useState<Account | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [envelope, setEnvelope] = useState<EncryptedVault | null>(null);
  const [data, setData] = useState<VaultData>(emptyVault);
  const [key, setKey] = useState<CryptoKey | null>(null);
  const [quickUnlocks, setQuickUnlocks] = useState<QuickUnlockConfig[]>([]);
  const [quickUnlockMethod, setQuickUnlockMethod] = useState<QuickUnlockMethod>("pin");
  const [quickSecret, setQuickSecret] = useState("");
  const [quickSecretConfirm, setQuickSecretConfirm] = useState("");
  const [pattern, setPattern] = useState<number[]>([]);
  const [confirmPattern, setConfirmPattern] = useState<number[]>([]);
  const [useMasterPassword, setUseMasterPassword] = useState(false);
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [recoveryEntry, setRecoveryEntry] = useState("");
  const [recoveryDisplay, setRecoveryDisplay] = useState("");
  const [recoveryConfirmed, setRecoveryConfirmed] = useState(false);
    const [recoveredByRecovery, setRecoveredByRecovery] = useState(false);
    const [recoveryKeyMemory, setRecoveryKeyMemory] = useState("");
  const [isNewVault, setIsNewVault] = useState(false);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [editing, setEditing] = useState<Credential | null>(null);
  const [credentialType, setCredentialType] = useState<CredentialType>("login");
  const [lockMethod, setLockMethod] = useState<LockMethod>("pin");
  const [credentialPattern, setCredentialPattern] = useState<number[]>([]);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All items");
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [selected, setSelected] = useState<Credential | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [drive, setDrive] = useState<DriveStatus>({ configured: false, connected: false });
  const [driveVersion, setDriveVersion] = useState<string | undefined>();
  const [saving, setSaving] = useState(false);
  const [generatorOptions, setGeneratorOptions] = useState({ length: 20, uppercase: true, lowercase: true, digits: true, symbols: true, excludeAmbiguous: true });
  const [generated, setGenerated] = useState("");
  const inactivity = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let active = true;
    async function loadAccount() {
      try {
        const response = await fetch("/api/drive/status", { cache: "no-store" });
        if (!response.ok) throw new Error("Could not verify the signed-in account.");
        const driveStatus = await response.json() as DriveStatus & { authenticated: boolean; user: Account | null };
        if (!active) return;
        setDrive(driveStatus);
        if (!driveStatus.authenticated || !driveStatus.user) return;
        setAccount(driveStatus.user);
        setEnvelope(readLocal(driveStatus.user.id));
        try {
          const configs = readQuickUnlocks(driveStatus.user.id);
          setQuickUnlocks(configs);
          if (configs[0]) setQuickUnlockMethod(configs[0].method);
        } catch {
          setError("Saved quick-unlock settings could not be read. Use your master password and replace them in Security settings.");
        }
      } catch (cause) {
        if (active) setError(cause instanceof Error ? cause.message : "Sign-in status is unavailable.");
      } finally {
        if (active) setAuthLoading(false);
      }
    }
    void loadAccount();
    const callbackResult = window.setTimeout(() => {
      const result = document.cookie.match(/(?:^|; )sv_drive_result=([^;]+)/)?.[1];
      if (!result) return;
      setStatus(result === "connected" ? "Signed in with Google. Your Drive is connected." : "Google sign-in did not complete. Try again and approve the requested access.");
      document.cookie = "sv_drive_result=; Max-Age=0; path=/; SameSite=Lax";
    }, 0);
    return () => { active = false; window.clearTimeout(callbackResult); };
  }, []);

  const lock = useCallback(() => {
    setKey(null);
    setData(emptyVault);
    setSelected(null);
    setRevealed(false);
    setMasterPassword("");
    setConfirmPassword("");
    setRecoveryEntry("");
      setRecoveryKeyMemory("");
      setRecoveredByRecovery(false);
    setQuickSecret("");
    setUseMasterPassword(false);
    if (inactivity.current) clearTimeout(inactivity.current);
    setStatus("Vault locked.");
  }, []);

  useEffect(() => {
    if (!key) return;
    const reset = () => {
      if (inactivity.current) clearTimeout(inactivity.current);
      inactivity.current = setTimeout(lock, 5 * 60 * 1000);
    };
    const visibility = () => {
      if (document.visibilityState === "hidden") {
        if (inactivity.current) clearTimeout(inactivity.current);
        inactivity.current = setTimeout(lock, 30_000);
      } else reset();
    };
    ["pointerdown", "keydown", "touchstart"].forEach((event) => window.addEventListener(event, reset));
    document.addEventListener("visibilitychange", visibility);
    reset();
    return () => {
      ["pointerdown", "keydown", "touchstart"].forEach((event) => window.removeEventListener(event, reset));
      document.removeEventListener("visibilitychange", visibility);
      if (inactivity.current) clearTimeout(inactivity.current);
    };
  }, [key, lock]);

  const categories = useMemo(() => ["All items", ...new Set(data.credentials.map((item) => item.category).filter(Boolean))], [data.credentials]);
  const visibleCredentials = useMemo(() => data.credentials.filter((item) => {
    const matchesQuery = `${item.title} ${item.username} ${item.url} ${item.category} ${credentialTypeLabels[item.type]}`.toLowerCase().includes(query.toLowerCase());
    return matchesQuery && (!favoritesOnly || item.favorite) && (category === "All items" || item.category === category);
  }).sort((a, b) => a.title.localeCompare(b.title)), [data.credentials, query, favoritesOnly, category]);

  async function activateVault(encrypted: EncryptedVault, vaultData: VaultData, vaultKey: CryptoKey) {
    if (!account) throw new Error("Sign in before opening a vault.");
    setEnvelope(encrypted);
    setData(vaultData);
    setKey(vaultKey);
    localStorage.setItem(userVaultKey(account.id), JSON.stringify(encrypted));
    setMasterPassword("");
    setConfirmPassword("");
    setError("");
  }

  async function handleCreate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError("");
    if (masterPassword !== confirmPassword) { setError("The passwords do not match."); return; }
    if (masterPassword.length < 14) { setError("Use at least 14 characters for your master password."); return; }
    setSaving(true);
    try {
      const created = await createVault(masterPassword, emptyVault);
      const unlocked = await unlockVault(created.envelope, masterPassword);
      setEnvelope(created.envelope); setData(emptyVault); setKey(unlocked.key);
      setRecoveryDisplay(created.recoveryKey); setRecoveryConfirmed(false); setIsNewVault(true);
      setMasterPassword(""); setConfirmPassword("");
    } catch { setError("Vault creation failed. Check that this browser supports secure Web Crypto."); }
    finally { setSaving(false); }
  }

  async function handleUnlock(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(""); setSaving(true);
    try {
      if (!envelope) throw new Error("No vault is available.");
      const unlocked = await unlockVault(envelope, masterPassword);
      await activateVault(envelope, unlocked.data, unlocked.key);
      setStatus("Vault unlocked.");
    } catch { setError("Could not unlock the vault. Check the master password or verify the encrypted backup is intact."); }
    finally { setSaving(false); }
  }

  async function handleQuickUnlock(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(""); setSaving(true);
    let secret: string | Uint8Array = quickSecret;
    try {
      if (!envelope) throw new Error("No vault is available.");
      const config = quickUnlocks.find((item) => item.method === quickUnlockMethod);
      if (!config) throw new Error("This quick-unlock method is not configured.");
      secret = config.method === "device" ? await getDeviceUnlockSecret(config) : quickSecret;
      const unlocked = await unlockQuickVault(envelope, config, secret);
      await activateVault(envelope, unlocked.data, unlocked.key);
      setQuickSecret("");
      setStatus("Vault unlocked with quick unlock.");
    } catch {
      setError("Quick unlock failed. Check your PIN, pattern, app password, or device authentication. You can use the master password instead.");
    } finally {
      if (secret instanceof Uint8Array) secret.fill(0);
      setSaving(false);
    }
  }

  async function saveQuickUnlock(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError("");
    if (!key) return;
    let secret: string | Uint8Array = quickSecret;
    let credentialId: string | undefined;
    let prfSalt: string | undefined;
    if (quickUnlockMethod === "pin" && !/^\d{8,}$/.test(quickSecret)) {
      setError("Use a PIN with at least 8 digits."); return;
    }
    if (quickUnlockMethod === "password" && quickSecret.length < 14) {
      setError("Use an app password with at least 14 characters."); return;
    }
    if (quickUnlockMethod === "pattern" && (pattern.length < 6 || new Set(pattern).size !== pattern.length || pattern.join(".") !== quickSecret)) {
      setError("Draw the same pattern twice using at least 6 different points."); return;
    }
    if (quickUnlockMethod !== "device" && quickSecret !== quickSecretConfirm) {
      setError("The quick-unlock entries do not match."); return;
    }
    setSaving(true);
    try {
      if (quickUnlockMethod === "device") {
        const device = await registerDeviceUnlock();
        secret = device.secret;
        credentialId = device.credentialId;
        prfSalt = device.prfSalt;
      }
      const config = await createQuickUnlock(key, quickUnlockMethod, secret, credentialId, prfSalt);
      const updated = [...quickUnlocks.filter((item) => item.method !== quickUnlockMethod), config];
      if (!account) throw new Error("Sign in before configuring quick unlock.");
      localStorage.setItem(userQuickUnlockKey(account.id), JSON.stringify(updated));
      setQuickUnlocks(updated);
      setQuickSecret(""); setQuickSecretConfirm(""); setPattern([]); setConfirmPattern([]);
      setStatus(`${quickUnlockLabels[quickUnlockMethod]} enabled for this browser.`);
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not set up quick unlock.");
    } finally {
      if (secret instanceof Uint8Array) secret.fill(0);
      setSaving(false);
    }
  }

  function removeQuickUnlock(method: QuickUnlockMethod) {
    const updated = quickUnlocks.filter((item) => item.method !== method);
    if (!account) return;
    localStorage.setItem(userQuickUnlockKey(account.id), JSON.stringify(updated));
    setQuickUnlocks(updated);
    if (quickUnlockMethod === method) setQuickUnlockMethod(updated[0]?.method ?? "pin");
    setStatus(`${quickUnlockLabels[method]} removed from this browser.`);
  }

  function clearQuickUnlocks() {
    if (account) localStorage.removeItem(userQuickUnlockKey(account.id));
    setQuickUnlocks([]);
  }

  async function handleRecovery(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(""); setSaving(true);
    try {
      if (!envelope) throw new Error("No vault is available.");
      const unlocked = await unlockWithRecovery(envelope, recoveryEntry);
      await activateVault(envelope, unlocked.data, unlocked.key);
      setRecoveryKeyMemory(recoveryEntry.trim()); setRecoveredByRecovery(true);
      setDialog(null); setStatus("Vault opened with the recovery key. Change the master password in Security settings.");
    } catch { setError("Recovery failed. Check the recovery key and encrypted vault file."); }
    finally { setSaving(false); }
  }

  async function commitData(next: VaultData) {
    if (!key || !envelope || !account) return;
    setSaving(true);
    try {
      const encrypted = await saveVault(key, next, envelope);
      setData(next); setEnvelope(encrypted); localStorage.setItem(userVaultKey(account.id), JSON.stringify(encrypted)); setStatus("Saved locally as encrypted data."); setError("");
    } catch { setError("Unable to validate or encrypt this change. Nothing was saved."); }
    finally { setSaving(false); }
  }

  function newCredential(type: CredentialType = "login") { setEditing(null); setCredentialType(type); setLockMethod("pin"); setCredentialPattern([]); setDialog("credential"); setError(""); }
  async function saveCredential(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const now = new Date().toISOString();
    const parsed = credentialSchema.safeParse({
      id: editing?.id ?? crypto.randomUUID(), type: form.get("type"), ...(credentialType !== "login" ? { lockMethod } : {}),
      title: form.get("title"), url: form.get("url") || "",
      username: form.get("username") || "", password: credentialType !== "login" && lockMethod === "pattern" ? credentialPattern.join(".") : form.get("password") || "", notes: form.get("notes") || "",
      category: form.get("category") || "", favorite: form.get("favorite") === "on", createdAt: editing?.createdAt ?? now, updatedAt: now,
    });
    if (!parsed.success) { setError(parsed.error.issues[0]?.message ?? "Check the credential fields."); return; }
    if (credentialType !== "login" && lockMethod === "pattern" && ![3, 6].includes(credentialPattern.length)) {
      setError("Draw a pattern using exactly 3 or 6 different points."); return;
    }
    const next = { ...data, credentials: editing ? data.credentials.map((item) => item.id === editing.id ? parsed.data : item) : [...data.credentials, parsed.data] };
    await commitData(next); setDialog(null); setRevealed(false); setSelected(parsed.data);
  }

  async function removeCredential(item: Credential) {
    if (!window.confirm(`Delete ${item.title}? This cannot be undone unless you have a backup.`)) return;
    await commitData({ ...data, credentials: data.credentials.filter((entry) => entry.id !== item.id) });
    setSelected(null);
  }

  async function copySecret(secret: string) {
    try {
      await navigator.clipboard.writeText(secret);
      setStatus("Copied. Clipboard clearing is best-effort; clipboard history and other apps may retain it.");
      window.setTimeout(async () => {
        try { if (await navigator.clipboard.readText() === secret) await navigator.clipboard.writeText(""); } catch { /* Clipboard permissions can prevent clearing. */ }
      }, 30_000);
    } catch { setError("Clipboard access was denied by the browser."); }
  }

  function downloadBackup() {
    if (!envelope) return;
    const url = URL.createObjectURL(exportEncryptedBackup(envelope));
    const link = document.createElement("a"); link.href = url; link.download = "secure-vault-encrypted-backup.json"; link.click(); URL.revokeObjectURL(url);
    setStatus("Encrypted backup exported. Store it separately from the recovery key.");
  }

  async function importBackup(file?: File) {
    if (!file) return;
    if (file.size > 1_500_000) { setError("Backup file is too large."); return; }
    try {
      const imported = parseEnvelope(await file.text());
      const password = window.prompt("Enter the master password for this backup. It will be checked locally.");
      if (password === null) return;
      const unlocked = await unlockVault(imported, password);
      if (!window.confirm(`Restore ${unlocked.data.credentials.length} items from this backup? The current local vault will be replaced only after verification.`)) return;
      clearQuickUnlocks();
      await activateVault(imported, unlocked.data, unlocked.key);
      setStatus("Encrypted backup restored and verified locally."); setDialog(null);
    } catch { setError("Backup could not be validated or unlocked. The current vault was not changed."); }
  }

  async function syncDrive() {
    setError(""); setSaving(true);
    try {
      if (!drive.connected) { connectDrive(); return; }
      if (!key || !envelope) {
        const response = await fetch("/api/drive/sync", { cache: "no-store" });
        if (!response.ok) {
          const result = await response.json() as { error?: string };
          throw new Error(result.error ?? "Google Drive sync failed.");
        }
        const result = await response.json() as { action: string; content?: string; file?: { version?: string } };
        if (result.action === "missing") { setStatus("No Drive vault found. Create a vault, then sync it to your Google Drive."); return; }
        if (result.content) {
          const downloaded = parseEnvelope(result.content);
          clearQuickUnlocks();
          setDriveVersion(result.file?.version);
          if (!account) throw new Error("Sign in before downloading a vault.");
          setEnvelope(downloaded); localStorage.setItem(userVaultKey(account.id), JSON.stringify(downloaded));
          setError("Drive vault downloaded. Enter its master password to unlock it.");
          return;
        }
      }
      if (driveVersion === undefined) {
        const remote = await fetch("/api/drive/sync", { cache: "no-store" });
        if (!remote.ok) throw new Error("Unable to check Drive version.");
        const remoteState = await remote.json() as { action: string; content?: string; file?: { version?: string } };
        if (remoteState.action === "downloaded" && remoteState.content) {
          const remoteEnvelope = parseEnvelope(remoteState.content);
          if (JSON.stringify(remoteEnvelope) !== JSON.stringify(envelope)) {
            setError("Drive contains a different vault revision. It was not overwritten; download and compare using a separate backup before proceeding.");
            return;
          }
          setDriveVersion(remoteState.file?.version);
          setStatus("Drive and local vault are in sync.");
          return;
        }
      }
      const response = await fetch("/api/drive/sync", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ envelope, version: driveVersion }) });
      const result = await response.json() as { action?: string; file?: { version?: string }; error?: string };
      if (!response.ok) throw new Error(result.error ?? "Sync failed.");
      setDriveVersion(result.file?.version); setStatus("Encrypted vault uploaded and downloaded again for byte-for-byte verification.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Drive sync failed. Check your connection, token status, and vault revision; no plaintext was sent.");
    }
    finally { setSaving(false); }
  }

  async function disconnect() {
    if (!window.confirm("Disconnect Google Drive? The Drive vault will remain in your account; local encrypted data also remains.")) return;
    try { await fetch("/api/drive/disconnect", { method: "POST" }); setDrive((current) => ({ ...current, connected: false })); setDriveVersion(undefined); setStatus("Drive disconnected; the encrypted vault remains in Google Drive."); }
    catch { setError("Could not disconnect Google Drive."); }
  }

  function connectDrive() {
    window.location.href = new URL("/api/drive/connect", window.location.origin).toString();
  }

  async function signOut() {
    setError(""); setSaving(true);
    try {
      const response = await fetch("/api/auth/logout", { method: "POST" });
      if (!response.ok) throw new Error("Could not sign out.");
      window.location.reload();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not sign out.");
      setSaving(false);
    }
  }

  async function updateMasterPassword(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError("");
    const form = new FormData(event.currentTarget);
    const oldPassword = String(form.get("oldPassword") ?? "");
    const nextPassword = String(form.get("newPassword") ?? "");
    if (nextPassword.length < 14 || nextPassword !== form.get("confirmNewPassword")) { setError("Use matching new passwords of at least 14 characters."); return; }
    try {
      const updated = recoveredByRecovery
        ? await resetMasterPasswordWithRecovery(envelope, recoveryKeyMemory, nextPassword)
        : await changeMasterPassword(envelope, oldPassword, nextPassword);
      if (!account) throw new Error("Sign in before changing the master password.");
      setEnvelope(updated); localStorage.setItem(userVaultKey(account.id), JSON.stringify(updated)); setStatus("Master password changed; the vault contents were not re-encrypted."); setDialog(null);
      setRecoveryKeyMemory(""); setRecoveredByRecovery(false);
    } catch { setError("Could not change the master password. Verify the current password."); }
  }

  const isUnlocked = Boolean(key);
  const canQuickUnlock = Boolean(envelope && quickUnlocks.length);
  const quickUnlockConfig = quickUnlocks.find((item) => item.method === quickUnlockMethod);
  const showingQuickUnlock = canQuickUnlock && !useMasterPassword;

  if (authLoading) {
    return <main className="grid min-h-screen place-items-center bg-[#f7f8fa] px-4 text-sm text-slate-500">Checking your secure sign-in…</main>;
  }

  return (
    <main className="min-h-screen bg-[#f7f8fa] text-[#17202d]">
      <header className="sticky top-0 z-50 border-b border-slate-200/80 bg-white/90 backdrop-blur">
        <div className="mx-auto flex max-w-[1440px] items-center justify-between px-4 py-3 sm:px-5 sm:py-4 lg:px-10">
          <a href="#home" className="flex min-w-0 items-center gap-2.5 sm:gap-3" aria-label="Secure Vault home">
            <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-[#183e35] text-white sm:h-10 sm:w-10"><ShieldIcon /></span>
            <span className="min-w-0"><span className="block text-[15px] font-bold tracking-tight">secure<span className="text-emerald-700">vault</span></span><span className="hidden text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400 sm:block">Personal password manager</span></span>
          </a>
          <div className="ml-2 flex shrink-0 items-center gap-2 sm:gap-3">
            {account && <span className="hidden max-w-48 truncate text-xs text-slate-500 md:block">{account.email}</span>}
            {account && <span className={`hidden items-center gap-2 rounded-full px-3 py-1.5 text-xs font-semibold sm:flex ${isUnlocked ? "bg-emerald-50 text-emerald-800" : "bg-slate-100 text-slate-600"}`}><span className={`h-1.5 w-1.5 rounded-full ${isUnlocked ? "bg-emerald-500" : "bg-slate-400"}`} />{isUnlocked ? "Vault unlocked" : "Vault locked"}</span>}
            {isUnlocked && <button onClick={lock} aria-label="Lock vault" className="button-quiet px-2.5 sm:px-4"><span className="hidden sm:inline">Lock vault</span><span className="sm:hidden">Lock</span><LockIcon /></button>}
            {account && <button onClick={() => void signOut()} disabled={saving} className="button-quiet px-2.5 sm:px-4"><span className="hidden sm:inline">Sign out</span><span className="sm:hidden">Exit</span></button>}
          </div>
        </div>
      </header>

      {!account ? <section className="mx-auto grid min-h-[calc(100dvh-60px)] max-w-6xl items-start gap-8 px-4 py-8 sm:min-h-[calc(100vh-73px)] sm:gap-12 sm:px-5 sm:py-12 lg:grid-cols-[1.08fr_.92fr] lg:items-center lg:px-10">
        <div className="order-2 max-w-xl lg:order-1">
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-emerald-100 bg-white px-3 py-1.5 text-xs font-semibold text-emerald-800"><span className="h-2 w-2 rounded-full bg-emerald-500" />Private encrypted vault</div>
          <h1 className="text-[2.6rem] font-semibold leading-[1.05] tracking-[-0.055em] text-[#172a26] sm:text-6xl">Your vault,<br /><span className="text-emerald-700">your Google Drive.</span></h1>
          <p className="mt-4 max-w-lg text-base leading-7 text-slate-500 sm:text-lg sm:leading-8">Sign in with Google to access your own Drive space. Your passwords remain encrypted in your browser; Google sign-in does not unlock your vault.</p>
        </div>
        <section className="order-1 mx-auto w-full max-w-md rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_24px_80px_-42px_rgba(21,50,43,.28)] sm:p-9 lg:order-2">
          <span className="grid h-12 w-12 place-items-center rounded-2xl bg-[#edf5f1] text-emerald-800"><DriveIcon /></span>
          <h2 className="mt-5 text-2xl font-semibold tracking-tight">Sign in to Secure Vault</h2>
          <p className="mt-2 text-sm leading-6 text-slate-500">Continue with Google to sign in and connect your private Drive app-data folder. The app only requests access to its own hidden folder.</p>
          <button onClick={connectDrive} disabled={!drive.configured} className="button-primary mt-6 w-full justify-center"><GoogleIcon />Continue with Google</button>
          {!drive.configured && <p className="mt-3 text-center text-xs text-slate-400">Google sign-in is not configured yet.</p>}
          {(status || error) && <p role={error ? "alert" : "status"} className={`mt-4 rounded-xl px-4 py-3 text-sm ${error ? "bg-rose-50 text-rose-800" : "bg-emerald-50 text-emerald-900"}`}>{error || status}</p>}
          <p className="mt-5 text-center text-xs leading-5 text-slate-400">Your Google account authenticates you. Your separate master password encrypts and unlocks your vault.</p>
        </section>
      </section> : !isUnlocked ? <section className="mx-auto grid min-h-[calc(100dvh-60px)] max-w-6xl items-start gap-8 px-4 py-8 sm:min-h-[calc(100vh-73px)] sm:gap-12 sm:px-5 sm:py-12 lg:grid-cols-[1.08fr_.92fr] lg:items-center lg:px-10">
        <div className="order-2 max-w-xl lg:order-1">
          <div className="mb-5 inline-flex max-w-full items-center gap-2 rounded-full border border-emerald-100 bg-white px-3 py-1.5 text-[11px] font-semibold text-emerald-800 sm:mb-7 sm:text-xs"><span className="h-2 w-2 shrink-0 rounded-full bg-emerald-500" /><span>Private by design</span><span className="text-slate-300">/</span><span className="truncate">Encryption stays in your browser</span></div>
          <h1 className="text-[2.6rem] font-semibold leading-[1.05] tracking-[-0.055em] text-[#172a26] sm:text-6xl">Your digital life,<br /><span className="text-emerald-700">under your key.</span></h1>
          <p className="mt-4 max-w-lg text-base leading-7 text-slate-500 sm:mt-6 sm:text-lg sm:leading-8">A calm, private home for your passwords. Your vault is encrypted on this device before it ever reaches a backup.</p>
          <div className="mt-6 grid max-w-md grid-cols-3 gap-2 sm:mt-9 sm:gap-3">
            {[{ value: "256-bit", label: "AES-GCM" }, { value: "Zero", label: "Plaintext uploads" }, { value: "You", label: "Own the recovery" }].map((item) => <div key={item.label} className="min-w-0 rounded-2xl border border-slate-200/80 bg-white p-3 sm:p-4"><p className="text-sm font-bold text-[#183e35] sm:text-base">{item.value}</p><p className="mt-1 text-[10px] leading-4 text-slate-500 sm:text-xs">{item.label}</p></div>)}
          </div>
          <p className="mt-5 flex max-w-md gap-3 rounded-2xl border border-amber-200/80 bg-amber-50/70 p-3 text-xs leading-5 text-amber-900 sm:mt-8 sm:p-4 sm:text-sm sm:leading-6"><span className="mt-0.5 shrink-0"><InfoIcon /></span><span><strong>Your master password cannot be reset.</strong> If it and the recovery key are lost, the vault cannot be recovered.</span></p>
        </div>
        <section className="order-1 mx-auto w-full max-w-md rounded-3xl border border-slate-200 bg-white p-5 shadow-[0_24px_80px_-42px_rgba(21,50,43,.28)] sm:rounded-[28px] sm:p-9 lg:order-2" aria-labelledby="unlock-title">
          <div className="mb-7 flex items-center justify-between"><span className="grid h-12 w-12 place-items-center rounded-2xl bg-[#edf5f1] text-emerald-800"><KeyIcon /></span><span className="text-xs font-semibold text-slate-400">AES-256-GCM · v1</span></div>
          <h2 id="unlock-title" className="text-2xl font-semibold tracking-tight">{envelope ? "Welcome back" : "Create your vault"}</h2>
          <p className="mt-2 text-sm leading-6 text-slate-500">{envelope ? showingQuickUnlock ? "Use a quick-unlock method saved in this browser, or switch to your master password." : "Unlock with your master password. Google sign-in does not unlock your vault." : "Choose a strong master password. You will also receive a one-time recovery key."}</p>
          <form onSubmit={envelope ? showingQuickUnlock ? handleQuickUnlock : handleUnlock : handleCreate} className="mt-7 space-y-4">
            {!envelope && <div className="space-y-2"><label className="label" htmlFor="master-password">Master password</label><input id="master-password" className="field" type="password" autoComplete="new-password" required minLength={14} maxLength={1024} value={masterPassword} onChange={(event) => setMasterPassword(event.target.value)} placeholder="At least 14 characters" />{masterPassword && <p className="text-xs text-slate-500">Strength estimate: <strong>{passwordStrength(masterPassword)}</strong>. A long unique passphrase is best.</p>}</div>}
            {envelope && showingQuickUnlock && <div className="space-y-3">
              <label className="label" htmlFor="quick-method">Quick-unlock method</label>
              <select id="quick-method" className="field" value={quickUnlockMethod} onChange={(event) => { setQuickUnlockMethod(event.target.value as QuickUnlockMethod); setQuickSecret(""); setPattern([]); }}>
                {quickUnlocks.map((item) => <option key={item.method} value={item.method}>{quickUnlockLabels[item.method]}</option>)}
              </select>
              {quickUnlockConfig?.method === "device" && <p className="text-sm text-slate-500">Confirm using your device&apos;s screen lock or biometric prompt.</p>}
              {quickUnlockConfig?.method === "pin" && <input aria-label="App PIN" className="field" type="password" inputMode="numeric" autoComplete="current-password" required value={quickSecret} onChange={(event) => setQuickSecret(event.target.value)} placeholder="Enter your 8+ digit PIN" />}
              {quickUnlockConfig?.method === "password" && <input aria-label="App password" className="field" type="password" autoComplete="current-password" required value={quickSecret} onChange={(event) => setQuickSecret(event.target.value)} placeholder="Enter your app password" />}
              {quickUnlockConfig?.method === "pattern" && <PatternInput value={pattern} onChange={(value) => { setPattern(value); setQuickSecret(value.join(".")); }} />}
            </div>}
            {envelope && !showingQuickUnlock && <div className="space-y-2"><label className="label" htmlFor="unlock-password">Master password</label><input id="unlock-password" className="field" type="password" autoComplete="current-password" required value={masterPassword} onChange={(event) => setMasterPassword(event.target.value)} placeholder="Enter your master password" /></div>}
            {!envelope && <div className="space-y-2"><label className="label" htmlFor="confirm-password">Confirm master password</label><input id="confirm-password" className="field" type="password" autoComplete="new-password" required value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} placeholder="Enter it again" /></div>}
            {error && <p role="alert" className="rounded-xl bg-rose-50 px-3 py-2 text-sm text-rose-800">{error}</p>}
            <button className="button-primary w-full justify-center" disabled={saving || (showingQuickUnlock && quickUnlockConfig?.method === "pattern" && pattern.length < 6)}>{saving ? "Working…" : envelope ? showingQuickUnlock ? `Unlock with ${quickUnlockLabels[quickUnlockMethod]}` : "Unlock vault" : "Create private vault"}<ArrowIcon /></button>
          </form>
          {envelope && canQuickUnlock && <button className="mt-3 w-full text-center text-sm font-semibold text-emerald-800 hover:text-emerald-950" onClick={() => { setUseMasterPassword(!useMasterPassword); setQuickSecret(""); setPattern([]); setError(""); }}>{showingQuickUnlock ? "Use master password instead" : "Use quick unlock instead"}</button>}
          {envelope && <form onSubmit={handleRecovery} className="mt-5 border-t border-slate-100 pt-5"><details><summary className="cursor-pointer text-center text-sm font-semibold text-slate-600 hover:text-emerald-800">Use a recovery key instead</summary><div className="mt-4 space-y-3"><label htmlFor="recovery-entry" className="label">Recovery key</label><input id="recovery-entry" className="field font-mono text-xs" value={recoveryEntry} onChange={(event) => setRecoveryEntry(event.target.value)} placeholder="Paste your saved recovery key" required /><button className="button-secondary w-full justify-center" disabled={saving}>Recover access</button></div></details></form>}
          <div className="my-6 flex items-center gap-3"><span className="h-px flex-1 bg-slate-100" /><span className="text-[10px] font-semibold uppercase tracking-[.16em] text-slate-400">Optional encrypted sync</span><span className="h-px flex-1 bg-slate-100" /></div>
          {!drive.connected ? <button onClick={connectDrive} disabled={!drive.configured} className="button-secondary w-full justify-center"><DriveIcon />{drive.configured ? "Reconnect Google Drive" : "Google Drive unavailable"}</button> :
            !envelope ? <button onClick={() => void syncDrive()} disabled={saving} className="button-secondary w-full justify-center"><DriveIcon />Check Google Drive for a vault</button> :
              <p className="rounded-xl bg-emerald-50 px-3 py-2 text-center text-xs text-emerald-800">Google Drive connected. Unlock your vault to sync.</p>}
          {!drive.configured && <p className="mt-2 text-center text-xs text-slate-400">The app administrator must finish Google and Neon configuration.</p>}
          {status && <p role="status" className="mt-4 text-center text-xs text-emerald-800">{status}</p>}
          <p className="mt-6 text-center text-xs leading-5 text-slate-400">Google authorization and vault unlocking are separate security steps.</p>
        </section>
      </section> : <div className="mx-auto grid max-w-[1440px] gap-6 px-4 py-5 sm:gap-8 sm:px-5 sm:py-8 lg:grid-cols-[245px_minmax(0,1fr)] lg:px-10">
        <aside className="order-2 space-y-5 lg:order-1 lg:space-y-6">
          <div className="rounded-2xl border border-slate-200 bg-white p-4"><div className="flex items-center justify-between"><div><p className="text-xs font-semibold uppercase tracking-wider text-slate-400">Your vault</p><p className="mt-1 text-2xl font-semibold">{data.credentials.length}<span className="ml-1 text-sm font-normal text-slate-400">items</span></p></div><span className="grid h-10 w-10 place-items-center rounded-xl bg-emerald-50 text-emerald-800"><ShieldIcon /></span></div><div className="mt-4 flex items-center gap-2 text-xs text-emerald-800"><span className="h-2 w-2 rounded-full bg-emerald-500" />Encrypted on this device</div></div>
          <nav aria-label="Vault filters" className="space-y-1">
            <button onClick={() => { setCategory("All items"); setFavoritesOnly(false); }} className={`nav-item ${category === "All items" && !favoritesOnly ? "nav-active" : ""}`}><GridIcon />All items<span className="ml-auto text-xs text-slate-400">{data.credentials.length}</span></button>
            <button onClick={() => { setFavoritesOnly(true); setCategory("All items"); }} className={`nav-item ${favoritesOnly ? "nav-active" : ""}`}><StarIcon />Favorites<span className="ml-auto text-xs text-slate-400">{data.credentials.filter((item) => item.favorite).length}</span></button>
          </nav>
          <div><p className="mb-2 px-3 text-[10px] font-bold uppercase tracking-[.16em] text-slate-400">Categories</p>{categories.filter((item) => item !== "All items").map((item) => <button key={item} onClick={() => { setCategory(item); setFavoritesOnly(false); }} className={`nav-item ${category === item ? "nav-active" : ""}`}><FolderIcon />{item}</button>)}{categories.length === 1 && <p className="px-3 py-2 text-xs text-slate-400">Categories appear as you add items.</p>}</div>
          <div className="rounded-2xl border border-slate-200 bg-white p-4"><p className="text-sm font-semibold">Sync status</p><p className="mt-1 text-xs leading-5 text-slate-500">{drive.connected ? "Google Drive is connected." : "Local-only encrypted storage."}</p><button onClick={syncDrive} disabled={saving} className="mt-3 w-full rounded-xl bg-slate-50 px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-emerald-50 hover:text-emerald-900">{drive.connected ? "Sync encrypted vault" : drive.configured ? "Connect Google Drive" : "Drive not configured"}</button>{drive.connected && <button onClick={disconnect} className="mt-2 w-full text-xs text-slate-400 hover:text-rose-700">Disconnect Drive</button>}</div>
          <div className="space-y-1 border-t border-slate-200 pt-4"><button className="nav-item" onClick={() => setDialog("generator")}><SparkIcon />Password generator</button><button className="nav-item" onClick={() => setDialog("backup")}><ArchiveIcon />Backup &amp; restore</button><button className="nav-item" onClick={() => setDialog("settings")}><SettingsIcon />Security settings</button></div>
        </aside>

        <section className="order-1 min-w-0 lg:order-2">
          <div className="mb-6 flex flex-wrap items-center justify-between gap-3 sm:mb-8 sm:items-end sm:gap-4"><div className="min-w-0"><p className="text-xs font-semibold uppercase tracking-[.16em] text-emerald-800">PERSONAL VAULT</p><h1 className="mt-2 text-2xl font-semibold tracking-tight sm:text-3xl">Your secure items</h1><p className="mt-1 text-sm text-slate-500">Save and find your passwords, phone locks, and app locks here.</p></div><button className="button-primary w-full sm:w-auto" onClick={() => newCredential()}><PlusIcon />Add item</button></div>
          <div className="mb-4 grid grid-cols-[minmax(0,1fr)_auto] gap-2 sm:mb-5 sm:flex sm:gap-3"><label className="relative col-span-2 min-w-0 sm:flex-1"><span className="sr-only">Search credentials</span><SearchIcon /><input className="field pl-11" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search your vault…" /></label><button onClick={() => setFavoritesOnly(!favoritesOnly)} aria-pressed={favoritesOnly} className={`button-secondary col-span-1 ${favoritesOnly ? "border-amber-200 bg-amber-50 text-amber-900" : ""}`}><StarIcon />Favorites</button><label className="sr-only" htmlFor="category-filter">Filter by category</label><select id="category-filter" className="field col-span-1 min-w-0 sm:w-48" value={category} onChange={(event) => { setCategory(event.target.value); setFavoritesOnly(false); }}><option>All items</option>{categories.filter((item) => item !== "All items").map((item) => <option key={item}>{item}</option>)}</select></div>
          <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm"><div className="grid grid-cols-[minmax(0,1fr)_minmax(130px,.65fr)_120px] gap-4 border-b border-slate-100 bg-slate-50/70 px-5 py-3 text-[10px] font-bold uppercase tracking-[.14em] text-slate-400 max-sm:grid-cols-[minmax(0,1fr)_auto]"><span>Item</span><span className="max-sm:hidden">Username</span><span className="text-right">Actions</span></div>
            {visibleCredentials.length ? visibleCredentials.map((item) => <div key={item.id} className="grid grid-cols-[minmax(0,1fr)_minmax(130px,.65fr)_120px] items-center gap-4 border-b border-slate-100 px-5 py-4 last:border-0 hover:bg-slate-50/70 max-sm:grid-cols-[minmax(0,1fr)_auto]">
              <button onClick={() => { setSelected(item); setRevealed(false); }} className="flex min-w-0 items-center gap-3 text-left"><span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-[#eef4f0] font-semibold text-emerald-900">{item.title.slice(0, 1).toUpperCase()}</span><span className="min-w-0"><span className="flex items-center gap-2 truncate font-semibold">{item.title}{item.favorite && <span className="text-amber-500"><StarIcon /></span>}</span><span className="block truncate text-xs text-slate-400">{item.url || item.category || credentialTypeLabels[item.type]}</span></span></button>
              <span className="truncate text-sm text-slate-500 max-sm:hidden">{item.username || "—"}</span><div className="flex justify-end gap-1"><button title="Copy username" aria-label={`Copy username for ${item.title}`} onClick={() => copySecret(item.username)} className="icon-button"><CopyIcon /></button><button title="View details" aria-label={`View ${item.title}`} onClick={() => { setSelected(item); setRevealed(false); }} className="icon-button"><ArrowIcon /></button></div>
            </div>) : <div className="px-6 py-16 text-center"><span className="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-emerald-50 text-emerald-800"><KeyIcon /></span><h3 className="mt-4 font-semibold">{query || favoritesOnly || category !== "All items" ? "No matches found" : "Your vault is ready"}</h3><p className="mx-auto mt-2 max-w-sm text-sm leading-6 text-slate-500">{data.credentials.length ? "Try another search or filter." : "Choose what you want to save. Your secret will be encrypted in this vault."}</p>{!data.credentials.length && <button className="button-primary mt-5" onClick={() => newCredential()}><PlusIcon />Add item</button>}</div>}
          </div>
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400"><span>{visibleCredentials.length} {visibleCredentials.length === 1 ? "item" : "items"} shown</span><span className="flex items-center gap-1.5"><LockIcon />Encrypted local vault <span className="mx-1">·</span> Autosave on changes</span></div>
          {(status || error) && <p role={error ? "alert" : "status"} className={`mt-4 rounded-xl px-4 py-3 text-sm ${error ? "bg-rose-50 text-rose-800" : "bg-emerald-50 text-emerald-900"}`}>{error || status}</p>}
        </section>
      </div>}

      {isNewVault && <div className="fixed inset-0 z-50 grid place-items-center overflow-y-auto bg-slate-950/45 p-3 sm:p-4"><section role="dialog" aria-modal="true" aria-labelledby="recovery-title" className="my-auto w-full max-w-lg rounded-3xl bg-white p-5 shadow-2xl sm:p-7"><span className="grid h-12 w-12 place-items-center rounded-2xl bg-amber-50 text-amber-800"><KeyIcon /></span><h2 id="recovery-title" className="mt-5 text-2xl font-semibold">Save your recovery key</h2><p className="mt-2 text-sm leading-6 text-slate-500">This key is shown once and is not stored in Google Drive or the backup. Keep it somewhere separate and secure.</p><div className="my-5 break-all rounded-xl border border-slate-200 bg-slate-50 p-4 font-mono text-sm leading-6">{recoveryDisplay}</div><button className="button-secondary w-full justify-center" onClick={() => copySecret(recoveryDisplay)}><CopyIcon />Copy recovery key</button><label className="mt-5 flex items-start gap-3 text-sm leading-6 text-slate-600"><input type="checkbox" checked={recoveryConfirmed} onChange={(event) => setRecoveryConfirmed(event.target.checked)} className="mt-1 accent-emerald-800" />I saved this recovery key separately and understand it cannot be recovered if lost.</label><button className="button-primary mt-5 w-full justify-center" disabled={!recoveryConfirmed} onClick={() => { if (!account || !envelope) return; setIsNewVault(false); localStorage.setItem(userVaultKey(account.id), JSON.stringify(envelope)); setRecoveryDisplay(""); setStatus("Vault created. Your encrypted vault is stored locally."); }}>Continue to my vault <ArrowIcon /></button></section></div>}

      {selected && isUnlocked && <div className="fixed inset-0 z-[60] flex justify-end bg-slate-950/35" onMouseDown={(event) => { if (event.target === event.currentTarget) setSelected(null); }}><section role="dialog" aria-modal="true" aria-labelledby="detail-title" className="h-full w-full max-w-lg overflow-auto bg-white p-6 shadow-2xl sm:p-8"><div className="flex items-start justify-between"><div className="flex items-center gap-3"><span className="grid h-12 w-12 place-items-center rounded-2xl bg-emerald-50 font-bold text-emerald-900">{selected.title.slice(0, 1).toUpperCase()}</span><div><h2 id="detail-title" className="text-xl font-semibold">{selected.title}</h2><p className="text-xs text-slate-400">{selected.category || credentialTypeLabels[selected.type]}</p></div></div><button aria-label="Close details" className="icon-button" onClick={() => setSelected(null)}>×</button></div><div className="mt-8 space-y-5">{selected.url && <DetailField label="Website" value={selected.url} href={selected.url} />}{selected.username && <DetailField label="Username" value={selected.username} copy={() => copySecret(selected.username)} />}<div><p className="label">{selected.type === "login" ? "Password" : selected.lockMethod === "pattern" ? "Unlock pattern" : "Lock PIN"}</p><div className="mt-2 flex items-center gap-2">{selected.lockMethod === "pattern" ? revealed ? <PatternInput value={selected.password.split(".").map(Number)} onChange={() => {}} readOnly /> : <span className="font-mono text-sm">••••••••</span> : <code className="min-w-0 flex-1 overflow-hidden rounded-xl bg-slate-50 px-3 py-3 font-mono text-sm">{revealed ? selected.password : "••••••••••••••••"}</code>}<button className="icon-button" aria-label={revealed ? "Mask secret" : "Reveal secret"} onClick={() => setRevealed(!revealed)}><EyeIcon /></button><button className="icon-button" aria-label="Copy secret" onClick={() => copySecret(selected.password)}><CopyIcon /></button></div><p className="mt-2 text-xs leading-5 text-slate-400">Clipboard clearing is best-effort and cannot remove clipboard history or copies made by other apps.</p></div>{selected.notes && <div><p className="label">Secure notes</p><p className="mt-2 whitespace-pre-wrap rounded-xl bg-slate-50 p-3 text-sm leading-6 text-slate-600">{selected.notes}</p></div>}<p className="text-xs text-slate-400">Updated {new Date(selected.updatedAt).toLocaleString()}</p></div><div className="mt-8 flex gap-3 border-t border-slate-100 pt-5"><button className="button-secondary flex-1 justify-center" onClick={() => { setEditing(selected); setCredentialType(selected.type); setLockMethod(selected.lockMethod ?? "pin"); setCredentialPattern(selected.lockMethod === "pattern" ? selected.password.split(".").map(Number) : []); setDialog("credential"); }}>Edit item</button><button className="button-danger" onClick={() => void removeCredential(selected)}>Delete</button></div></section></div>}

      {dialog && <div className="fixed inset-0 z-40 grid place-items-center overflow-y-auto bg-slate-950/35 p-3 sm:p-4" onMouseDown={(event) => { if (event.target === event.currentTarget) setDialog(null); }}><section role="dialog" aria-modal="true" className="my-auto max-h-[calc(100dvh-1.5rem)] w-full max-w-xl overflow-y-auto rounded-3xl bg-white p-5 shadow-2xl sm:my-6 sm:max-h-[calc(100vh-3rem)] sm:p-8">
        <div className="sticky top-0 z-10 -mx-5 -mt-5 mb-6 flex items-start justify-between bg-white px-5 pt-5 sm:-mx-8 sm:-mt-8 sm:px-8 sm:pt-8"><div><p className="text-xs font-bold uppercase tracking-[.16em] text-emerald-800">SECURE VAULT</p><h2 className="mt-1 text-2xl font-semibold">{dialog === "credential" ? editing ? "Edit item" : credentialType === "phone-lock" ? "Save phone lock" : credentialType === "app-lock" ? "Save app lock" : "Save password" : dialog === "generator" ? "Password generator" : dialog === "settings" ? "Security settings" : dialog === "backup" ? "Backup & restore" : "Recovery"}</h2></div><button className="icon-button" onClick={() => setDialog(null)} aria-label="Close">×</button></div>
        {dialog === "credential" && <form key={editing?.id ?? "new"} onSubmit={saveCredential} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div><label className="label" htmlFor="credential-type">Item type</label><select className="field mt-2" id="credential-type" name="type" value={credentialType} onChange={(event) => setCredentialType(event.target.value as CredentialType)}>{Object.entries(credentialTypeLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></div>
            <div><label className="label" htmlFor="credential-title">{credentialType === "login" ? "Service name" : credentialType === "phone-lock" ? "Phone or device name" : "App name"} *</label><input className="field mt-2" id="credential-title" name="title" required maxLength={120} defaultValue={editing?.title} placeholder={credentialType === "login" ? "e.g. Email" : credentialType === "phone-lock" ? "e.g. Personal phone" : "e.g. Banking app"} /></div>
          </div>
          <div><label className="label" htmlFor="credential-category">Category</label><input className="field mt-2" id="credential-category" name="category" maxLength={80} defaultValue={editing?.category} placeholder="Personal, Work…" /></div>
          {credentialType === "login" && <div><label className="label" htmlFor="credential-url">Website URL</label><input className="field mt-2" id="credential-url" name="url" type="url" maxLength={2048} defaultValue={editing?.url} placeholder="https://example.com" /></div>}
          {credentialType !== "login" && <div><label className="label" htmlFor="lock-method">Lock method</label><select id="lock-method" className="field mt-2" value={lockMethod} onChange={(event) => { setLockMethod(event.target.value as LockMethod); setCredentialPattern([]); setError(""); }}><option value="pin">PIN</option><option value="pattern">Pattern</option></select></div>}
          <div className="grid gap-4 sm:grid-cols-2">
            {credentialType === "login" && <div><label className="label" htmlFor="credential-username">Username or email</label><input className="field mt-2" id="credential-username" name="username" maxLength={320} autoComplete="off" defaultValue={editing?.username} /></div>}
            {credentialType !== "login" && lockMethod === "pattern" ? <div className="sm:col-span-2"><p className="label mb-2">Draw unlock pattern (exactly 3 or 6 dots)</p><PatternInput value={credentialPattern} onChange={setCredentialPattern} /><input type="hidden" name="password" value={credentialPattern.join(".")} /></div> :
              <div className={credentialType === "login" ? "" : "sm:col-span-2"}><label className="label" htmlFor="credential-password">{credentialType === "login" ? "Password" : "Lock PIN"} *</label><div className="mt-2 flex gap-2"><input className="field min-w-0" id="credential-password" name="password" type="password" required maxLength={4096} autoComplete="new-password" defaultValue={editing && !(editing.lockMethod === "pattern") ? editing.password : undefined} /><button type="button" title="Generate password" className="button-secondary px-3" onClick={() => { setDialog("generator"); setGenerated(""); }}><SparkIcon /></button></div>{credentialType !== "login" && <p className="mt-2 text-xs text-slate-500">This secret is encrypted with your vault and only revealed when you open the item.</p>}</div>}
          </div>
          <div><label className="label" htmlFor="credential-notes">Secure notes</label><textarea className="field mt-2 min-h-24 resize-y" id="credential-notes" name="notes" maxLength={10000} defaultValue={editing?.notes} placeholder={credentialType === "phone-lock" ? "Optional device details or recovery notes" : credentialType === "app-lock" ? "Optional app details or recovery notes" : ""} /></div>
          <label className="flex items-center gap-2 text-sm text-slate-600"><input name="favorite" type="checkbox" defaultChecked={editing?.favorite} className="accent-emerald-800" />Mark as favorite</label>
          {error && <p role="alert" className="text-sm text-rose-800">{error}</p>}
          <div className="flex justify-end gap-3 pt-2"><button type="button" className="button-secondary" onClick={() => setDialog(null)}>Cancel</button><button className="button-primary" disabled={saving}>Save securely</button></div>
        </form>}
        {dialog === "generator" && <div className="space-y-5"><div className="rounded-2xl bg-slate-50 p-4"><div className="flex items-center justify-between"><label className="label" htmlFor="gen-length">Length</label><span className="font-mono text-sm font-semibold">{generatorOptions.length}</span></div><input id="gen-length" type="range" min="8" max="64" value={generatorOptions.length} onChange={(event) => setGeneratorOptions({ ...generatorOptions, length: Number(event.target.value) })} className="mt-3 w-full accent-emerald-800" /></div><div className="grid grid-cols-2 gap-3">{([["uppercase", "Uppercase A–Z"], ["lowercase", "Lowercase a–z"], ["digits", "Numbers 0–9"], ["symbols", "Symbols"]] as const).map(([keyName, label]) => <label key={keyName} className="flex items-center gap-2 rounded-xl border border-slate-200 p-3 text-sm"><input type="checkbox" checked={generatorOptions[keyName]} onChange={(event) => setGeneratorOptions({ ...generatorOptions, [keyName]: event.target.checked })} className="accent-emerald-800" />{label}</label>)}</div><label className="flex items-center gap-2 text-sm text-slate-600"><input type="checkbox" checked={generatorOptions.excludeAmbiguous} onChange={(event) => setGeneratorOptions({ ...generatorOptions, excludeAmbiguous: event.target.checked })} className="accent-emerald-800" />Exclude similar characters (I, l, 1, O, 0)</label><div className="rounded-xl border border-slate-200 bg-slate-50 p-4"><p className="break-all font-mono text-sm leading-6">{generated || "Generate a password to preview it"}</p>{generated && <p className="mt-2 text-xs text-slate-500">Estimated strength: {passwordStrength(generated)} · Indicator is not a guarantee.</p>}</div><div className="flex justify-end gap-3"><button className="button-secondary" onClick={() => { try { setGenerated(generatePassword(generatorOptions)); setError(""); } catch { setError("Choose at least one character type and a valid length."); } }}>Generate</button>{generated && <button className="button-primary" onClick={() => { void copySecret(generated); if (editing) { setDialog("credential"); setTimeout(() => { const input = document.getElementById("credential-password") as HTMLInputElement | null; if (input) { const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set; setter?.call(input, generated); input.dispatchEvent(new Event("input", { bubbles: true })); } }, 0); } else setDialog(null); }}>Copy password</button>}</div>{error && <p role="alert" className="text-sm text-rose-800">{error}</p>}</div>}
        {dialog === "settings" && <div className="space-y-6">
          <div className="rounded-2xl border border-emerald-100 bg-emerald-50/60 p-4"><p className="font-semibold text-emerald-950">Encryption status</p><p className="mt-1 text-sm leading-6 text-emerald-900/75">AES-256-GCM · PBKDF2-HMAC-SHA-256 · 600,000 iterations. Active keys and decrypted credentials are held in memory while unlocked; optional quick unlock stores only an encrypted local key copy. JavaScript cannot guarantee secure memory erasure.</p></div>
          <section className="space-y-4 border-t border-slate-100 pt-4">
            <div><h3 className="font-semibold">Quick unlock on this browser</h3><p className="mt-1 text-sm leading-6 text-slate-500">Quick unlock encrypts a copy of the vault key in local browser storage. PINs and patterns can be guessed offline if someone copies that storage; use a strong app password or device unlock where supported.</p></div>
            <form onSubmit={saveQuickUnlock} className="space-y-3">
              <label className="label" htmlFor="quick-setup-method">Method</label>
              <select id="quick-setup-method" className="field" value={quickUnlockMethod} onChange={(event) => { setQuickUnlockMethod(event.target.value as QuickUnlockMethod); setQuickSecret(""); setQuickSecretConfirm(""); setPattern([]); setConfirmPattern([]); setError(""); }}>
                {(Object.keys(quickUnlockLabels) as QuickUnlockMethod[]).map((method) => <option key={method} value={method}>{quickUnlockLabels[method]}</option>)}
              </select>
              {quickUnlockMethod === "device" && <p className="text-sm leading-6 text-slate-500">Uses a platform passkey with biometric or device-PIN verification. Your browser/device must support the WebAuthn PRF extension. The vault master password remains available as a fallback.</p>}
              {quickUnlockMethod === "pin" && <>
                <input aria-label="New app PIN" className="field" type="password" inputMode="numeric" autoComplete="new-password" value={quickSecret} onChange={(event) => setQuickSecret(event.target.value)} placeholder="New PIN (at least 8 digits)" />
                <input aria-label="Confirm app PIN" className="field" type="password" inputMode="numeric" autoComplete="new-password" value={quickSecretConfirm} onChange={(event) => setQuickSecretConfirm(event.target.value)} placeholder="Confirm PIN" />
              </>}
              {quickUnlockMethod === "password" && <>
                <input aria-label="New app password" className="field" type="password" autoComplete="new-password" value={quickSecret} onChange={(event) => setQuickSecret(event.target.value)} placeholder="New app password (14+ characters)" />
                <input aria-label="Confirm app password" className="field" type="password" autoComplete="new-password" value={quickSecretConfirm} onChange={(event) => setQuickSecretConfirm(event.target.value)} placeholder="Confirm app password" />
              </>}
              {quickUnlockMethod === "pattern" && <div className="grid gap-3 sm:grid-cols-2">
                <div><p className="label mb-2">Draw pattern</p><PatternInput value={pattern} onChange={(value) => { setPattern(value); setQuickSecret(value.join(".")); }} /></div>
                <div><p className="label mb-2">Confirm pattern</p><PatternInput value={confirmPattern} onChange={(value) => { setConfirmPattern(value); setQuickSecretConfirm(value.join(".")); }} /></div>
              </div>}
              <button className="button-secondary" disabled={saving}>{saving ? "Setting up…" : `Enable ${quickUnlockLabels[quickUnlockMethod]}`}</button>
              {error && <p role="alert" className="text-sm text-rose-800">{error}</p>}
            </form>
            {quickUnlocks.length > 0 && <ul className="space-y-2">{quickUnlocks.map((item) => <li key={item.method} className="flex items-center justify-between rounded-xl border border-slate-200 px-3 py-2"><span className="text-sm font-medium">{quickUnlockLabels[item.method]} enabled</span><button className="button-quiet min-h-0 px-2 py-1 text-xs" onClick={() => removeQuickUnlock(item.method)}>Remove</button></li>)}</ul>}
          </section>
          <form onSubmit={updateMasterPassword} className="space-y-3 border-t border-slate-100 pt-4"><h3 className="font-semibold">Change master password</h3><input className="field" name="oldPassword" type="password" autoComplete="current-password" required placeholder="Current master password" /><input className="field" name="newPassword" type="password" minLength={14} autoComplete="new-password" required placeholder="New password (14+ characters)" /><input className="field" name="confirmNewPassword" type="password" minLength={14} autoComplete="new-password" required placeholder="Confirm new password" /><button className="button-secondary">Rewrap vault key</button></form>
          <div className="border-t border-slate-100 pt-4"><h3 className="font-semibold">Recovery key</h3><p className="mt-1 text-sm leading-6 text-slate-500">The recovery key protects the random vault key independently of your master password. Keep it offline and separate from backups.</p><button className="button-secondary mt-3" onClick={() => { setDialog("recovery"); setRecoveryEntry(""); }}>Test recovery key</button></div>
          <div className="border-t border-slate-100 pt-4"><p className="text-sm font-semibold">Inactivity lock</p><p className="mt-1 text-sm text-slate-500">Locks after five minutes idle or 30 seconds in a hidden tab.</p></div>
        </div>}
        {dialog === "recovery" && <form onSubmit={handleRecovery} className="space-y-4"><p className="text-sm leading-6 text-slate-500">Enter the recovery key to open the vault. Store and test your key before relying on it. A successful test does not change your master password.</p><label className="label" htmlFor="recovery-modal">Recovery key</label><textarea id="recovery-modal" className="field min-h-24 font-mono text-xs" value={recoveryEntry} onChange={(event) => setRecoveryEntry(event.target.value)} required /><button className="button-primary" disabled={saving}>Verify recovery key</button>{error && <p role="alert" className="text-sm text-rose-800">{error}</p>}</form>}
        {dialog === "backup" && <div className="space-y-5"><div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-950"><strong>Encrypted backups only.</strong> This file contains ciphertext and key-wrap metadata, not plaintext credentials or the recovery key. Keep multiple copies in separate secure locations.</div><button className="button-primary w-full justify-center" onClick={downloadBackup}><ArchiveIcon />Export encrypted backup</button><label className="button-secondary w-full justify-center"><UploadIcon />Choose encrypted backup<input type="file" accept="application/json,.json" className="sr-only" onChange={(event) => void importBackup(event.target.files?.[0])} /></label><p className="text-xs leading-5 text-slate-400">Restore validates and decrypts the file locally before replacing the current local vault. Drive contents are unchanged. For a safe restore test, use a separate browser profile and a duplicate backup copy.</p></div>}
      </section></div>}
      <footer className="mx-auto max-w-[1440px] px-5 pb-8 text-center text-[11px] leading-5 text-slate-400 lg:px-10">Private localhost application · No analytics · Never expose this development server publicly · Use a current, trusted browser.</footer>
    </main>
  );
}

function PatternInput({ value, onChange, readOnly = false }: { value: number[]; onChange: (value: number[]) => void; readOnly?: boolean }) {
  return <div>
    <div className="grid max-w-44 grid-cols-3 gap-2 rounded-2xl border border-slate-200 bg-slate-50 p-3" aria-label="Unlock pattern points">
      {Array.from({ length: 9 }, (_, index) => {
        const order = value.indexOf(index);
        return <button
          key={index}
          type="button"
          aria-label={`Pattern point ${index + 1}${order >= 0 ? `, sequence ${order + 1}` : ""}`}
          aria-pressed={order >= 0}
          disabled={readOnly}
          onClick={() => onChange(order >= 0 ? [] : [...value, index])}
          className={`grid h-10 w-10 place-items-center rounded-full border text-xs font-semibold ${order >= 0 ? "border-emerald-800 bg-emerald-800 text-white" : "border-slate-300 bg-white text-slate-500 hover:border-emerald-600"} ${readOnly ? "cursor-default" : ""}`}
        >{order >= 0 ? order + 1 : "·"}</button>;
      })}
    </div>
    <div className="mt-2 flex items-center justify-between text-xs text-slate-500"><span>{value.length} points</span>{!readOnly && <button type="button" className="font-semibold text-emerald-800" onClick={() => onChange([])}>Clear</button>}</div>
  </div>;
}

function DetailField({ label, value, href, copy }: { label: string; value: string; href?: string; copy?: () => void }) {
  return <div><p className="label">{label}</p><div className="mt-2 flex items-center gap-2 rounded-xl bg-slate-50 p-3"><p className="min-w-0 flex-1 truncate text-sm">{href ? <a href={href} target="_blank" rel="noreferrer" className="text-emerald-800 underline">{value}</a> : value}</p>{copy && <button onClick={copy} className="icon-button" aria-label={`Copy ${label}`}><CopyIcon /></button>}</div></div>;
}

function ShieldIcon() { return <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3 19 6v5c0 5-3 8-7 10-4-2-7-5-7-10V6l7-3Z"/><path d="m9 12 2 2 4-4"/></svg>; }
function KeyIcon() { return <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="8" cy="15" r="4"/><path d="m11 12 8-8m-2 2 3 3m-6-1 3 3"/></svg>; }
function LockIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 1 1 8 0v3m-4 5v2"/></svg>; }
function InfoIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 11v5m0-8h.01"/></svg>; }
function ArrowIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M5 12h14m-6-6 6 6-6 6"/></svg>; }
function DriveIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="m9 3-7 12 3 5h14l3-5-7-12H9Z"/><path d="m9 3 7 12m6 0H2m3 5 7-12"/></svg>; }
function GoogleIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true"><path fill="#4285F4" d="M21.6 12.23c0-.71-.06-1.39-.18-2.05H12v3.88h5.38a4.6 4.6 0 0 1-2 3.02v2.52h3.24c1.9-1.75 2.98-4.33 2.98-7.37Z"/><path fill="#34A853" d="M12 22c2.7 0 4.97-.9 6.62-2.4l-3.24-2.52c-.9.6-2.05.96-3.38.96-2.6 0-4.8-1.75-5.58-4.1H3.07v2.6A10 10 0 0 0 12 22Z"/><path fill="#FBBC05" d="M6.42 13.94a6 6 0 0 1 0-3.88v-2.6H3.07a10 10 0 0 0 0 9.08l3.35-2.6Z"/><path fill="#EA4335" d="M12 5.96c1.47 0 2.79.5 3.83 1.5l2.87-2.86C16.96 2.98 14.7 2 12 2a10 10 0 0 0-8.93 5.46l3.35 2.6C7.2 7.7 9.4 5.96 12 5.96Z"/></svg>; }
function GridIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></svg>; }
function StarIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-3-5.6 3 1.1-6.2L3 9.6l6.2-.9L12 3Z"/></svg>; }
function FolderIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M3 6a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6Z"/></svg>; }
function SparkIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="m12 3 1.4 5.6L19 10l-5.6 1.4L12 17l-1.4-5.6L5 10l5.6-1.4L12 3Zm7 12 .7 2.3L22 18l-2.3.7L19 21l-.7-2.3L16 18l2.3-.7L19 15Z"/></svg>; }
function ArchiveIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M4 4h16v4H4zM6 8v12h12V8m-8 4h4"/></svg>; }
function SettingsIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1 1.2 1-1.2 2.1-1.5-.5a8 8 0 0 1-1.5.9l-.3 1.6h-2.4l-.3-1.6a8 8 0 0 1-1.5-.9l-1.5.5-1.2-2.1 1.2-1a7 7 0 0 1 0-1.8l-1.2-1 1.2-2.1 1.5.5a8 8 0 0 1 1.5-.9l.3-1.6h2.4l.3 1.6a8 8 0 0 1 1.5.9l1.5-.5 1.2 2.1-1.2 1a7 7 0 0 1 0 1.7Z" transform="translate(-1 -1) scale(.95)"/></svg>; }
function PlusIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 5v14m-7-7h14"/></svg>; }
function SearchIcon() { return <svg viewBox="0 0 24 24" className="pointer-events-none absolute left-4 top-3.5 h-4 w-4 text-slate-400" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="10.8" cy="10.8" r="6.8"/><path d="m16 16 5 5"/></svg>; }
function CopyIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></svg>; }
function EyeIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg>; }
function UploadIcon() { return <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 16V4m-5 5 5-5 5 5M4 15v5h16v-5"/></svg>; }