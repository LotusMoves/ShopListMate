// static/js/main.js

async function deriveKey(password, salt, iterations, keyLength) {

  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  const saltBuffer = encoder.encode(salt);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
  const key = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    keyLength * 8
  );
  return new Uint8Array(key);
}

async function deriveAESKey(password, salt, iterations, keyLength) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  const saltBuffer = encoder.encode(salt);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: keyLength * 8 },
    true,
    ['encrypt', 'decrypt']
  );
  return derivedKey;
}


async function encryptPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16)).join('');
  const iterations = 1000000;
  const keyLength = 32;

  const key = await deriveKey(password, salt, iterations, keyLength);
  return { encryptedPassword: btoa(String.fromCharCode.apply(null, key)), salt };
}

async function encryptPasswordWithSalt(password, salt) {
  const iterations = 1000000;
  const keyLength = 32;

  const key = await deriveKey(password, salt, iterations, keyLength);
  return btoa(String.fromCharCode.apply(null, key));
}


async function encryptData(data, aesKey) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    aesKey,
    dataBuffer
  );

  const encryptedDataBase64 = btoa(
    String.fromCharCode.apply(null, new Uint8Array(encryptedData))
  );
  const ivBase64 = btoa(String.fromCharCode.apply(null, iv));

  return ivBase64 + '.' + encryptedDataBase64;
}

async function decryptData(encryptedData, aesKey) {
   if (!encryptedData) {
    return null;
  }
  const [ivBase64, encryptedDataBase64] = encryptedData.split('.');
  const iv = Uint8Array.from(atob(ivBase64), (c) => c.charCodeAt(0));
  const encryptedDataBuffer = Uint8Array.from(
    atob(encryptedDataBase64),
    (c) => c.charCodeAt(0)
  );

  const dataBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    aesKey,
    encryptedDataBuffer
  );

  return new TextDecoder().decode(dataBuffer);
}

