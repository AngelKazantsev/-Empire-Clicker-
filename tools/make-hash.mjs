// Генератор хеша пароля администратора. Запуск: node tools/make-hash.mjs
// Результат вставьте в Netlify как переменную ADMIN_PASSWORD_HASH (пароль в открытом виде тогда нигде не хранится).
import crypto from 'node:crypto';
import readline from 'node:readline';
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
rl.question('Введите пароль администратора: ', pw => {
  rl.close();
  if (!pw) { console.error('Пустой пароль'); process.exit(1); }
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  console.log('\nADMIN_PASSWORD_HASH=scrypt$' + salt + '$' + hash + '\n');
});
