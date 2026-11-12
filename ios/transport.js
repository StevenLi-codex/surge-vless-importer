'use strict';
const { validateRemote } = require('./runtime');
function createFetcher(client) {
  return async function fetchSubscription(source) {
    try {
      let url = validateRemote(source);
      for (let redirects = 0; redirects <= 3; redirects++) {
        const result = await new Promise((resolve, reject) => {
          client.get({ url, headers: { 'User-Agent': 'clash.meta', 'Accept-Encoding': 'identity' }, timeout: 10, 'auto-cookie': false, 'auto-redirect': false },
            (error, response, body) => error ? reject(new Error('network')) : resolve({ response, body }));
        });
        if (!result.response) throw new Error('response');
        const status = Number(result.response.status);
        if ([301, 302, 303, 307, 308].includes(status)) {
          const entry = Object.entries(result.response.headers || {}).find(([key]) => key.toLowerCase() === 'location');
          if (!entry || redirects === 3) throw new Error('redirect');
          url = validateRemote(new URL(entry[1], url).href);
          continue;
        }
        if (status !== 200 || typeof result.body !== 'string' || new TextEncoder().encode(result.body).length > 2 * 1024 * 1024) throw new Error('response');
        return result.body;
      }
      throw new Error('redirect');
    } catch (_) { throw new Error('订阅下载失败，请检查 HTTPS 链接及网络'); }
  };
}
module.exports = { createFetcher };
