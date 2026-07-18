// content.enc 복호화 (build.js의 encryptJSON과 동일 방식: PBKDF2 + AES-GCM)
const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

export async function decryptContent(encText, password) {
  const env = JSON.parse(encText);
  const enc = new TextEncoder();
  const salt = b64ToBytes(env.kdf.salt);
  const iv = b64ToBytes(env.iv);
  const data = b64ToBytes(env.data);

  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: env.kdf.iterations, hash: env.kdf.hash || "SHA-256" },
    baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
  );
  // 비밀번호가 틀리면 AES-GCM 무결성 검증 실패로 예외 발생
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return JSON.parse(new TextDecoder().decode(plain));
}
