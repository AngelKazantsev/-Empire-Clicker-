import { makeStoreFactory } from '../lib/storage.mjs';
import { makeBackup } from '../lib/backup.mjs';

// Ежедневная автоматическая копия базы (работает на Netlify; на своём сервере её делает server/index.mjs).
export default async () => {
  const res = await makeBackup(await makeStoreFactory());
  console.log('backup', JSON.stringify(res));
  return new Response('ok');
};
export const config = { schedule: '@daily' };
