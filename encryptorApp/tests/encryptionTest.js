async function runAllCsvTests() {
  runEncryptionTests();
  runModifyRowTests();
}

async function runEncryptionTests() {
  const results = [];

  results.push(await runEncryptionTest(
    "test123",
    "name,password\nAlice,1234\nBob,5678",
    "Simple ASCII Test"
  ));

  results.push(await runEncryptionTest(
    "P@$$w0rd🔐",
    `name,password,note
Alice,1234,emoji 😎
Bob,5678,quote "safe"
李雷,密码123,中文测试
Élodie,abc123,accenté
newline,test,"line1\\nline2"`,
    "Advanced Unicode & Special Characters Test"
  ));

  const output = document.getElementById("testResult");
  output.innerHTML = results.map(r => r.msg).join('\n');
  output.style.color = results.every(r => r.success) ? "green" : "red";
}

async function runEncryptionTest(password, csvString, label) {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  try {
    const encoded = enc.encode(csvString);
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
    const result = dec.decode(decrypted);

    const success = result === csvString;
    return {
      success,
      msg: success
        ? `✅ ${label} passed.`
        : `❌ ${label} failed: Decrypted content did not match.`
    };
  } catch (e) {
    return {
      success: false,
      msg: `❌ ${label} failed: Exception during encryption/decryption.`
    };
  }
}
