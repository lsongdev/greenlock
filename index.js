import {
  html,
  render,
  useEffect,
  useState,
} from 'https://lsong.org/scripts/react/index.js';
import { AcmeClient } from './acme.js';
import { createCSR, exportPrivateKey, generateKeyPair } from './crypto.js';


const PROVIDERS = [
  ['Let’s Encrypt', 'https://acme-v02.api.letsencrypt.org/directory'],
  ['Let’s Encrypt Staging', 'https://acme-staging-v02.api.letsencrypt.org/directory'],
];

function normalizeDomains(value) {
  return [...new Set(value.split(/[\s,]+/).filter(Boolean).map(input => {
    const wildcard = input.startsWith('*.');
    const value = wildcard ? input.slice(2) : input;
    const url = new URL(`https://${value}`);
    if (!url.hostname || url.hostname.includes(':') || url.pathname !== '/' || url.search || url.hash) {
      throw new Error(`Invalid domain: ${input}`);
    }
    return wildcard ? `*.${url.hostname}` : url.hostname;
  }))];
}

function download(name, content) {
  const url = URL.createObjectURL(new Blob([content], { type: 'application/x-pem-file' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function App() {
  const [directoryUrl, setDirectoryUrl] = useState(PROVIDERS[0][1]);
  const [directory, setDirectory] = useState(null);
  const [client, setClient] = useState(null);
  const [email, setEmail] = useState('');
  const [accountKey, setAccountKey] = useState('');
  const [accountUrl, setAccountUrl] = useState('');
  const [domainInput, setDomainInput] = useState('');
  const [orderUrl, setOrderUrl] = useState('');
  const [order, setOrder] = useState(null);
  const [authorizations, setAuthorizations] = useState([]);
  const [selected, setSelected] = useState({});
  const [certificateKey, setCertificateKey] = useState('');
  const [csr, setCsr] = useState(null);
  const [certificate, setCertificate] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    const acme = new AcmeClient(directoryUrl);
    setClient(acme);
    setDirectory(null);
    setAccountKey('');
    setAccountUrl('');
    setOrderUrl('');
    setOrder(null);
    setAuthorizations([]);
    setSelected({});
    setCertificateKey('');
    setCsr(null);
    setCertificate('');
    setError('');
    acme.init()
      .then(value => active && setDirectory(value))
      .catch(err => active && setError(err.message));
    return () => { active = false; };
  }, [directoryUrl]);

  async function run(action) {
    setBusy(true);
    setError('');
    try {
      await action();
    } catch (err) {
      console.error(err);
      setError(err.message || String(err));
    } finally {
      setBusy(false);
    }
  }

  async function createAccount(event) {
    event.preventDefault();
    await run(async () => {
      const keyPair = await generateKeyPair();
      await client.setKeyPair(keyPair);
      const privateKey = await exportPrivateKey(keyPair);
      await client.createAccount({ contact: [`mailto:${email}`], termsOfServiceAgreed: true });
      setAccountKey(privateKey);
      setAccountUrl(client.accountUrl);
    });
  }

  async function refreshOrder(url = orderUrl) {
    const nextOrder = await client.getOrder(url);
    const auths = await Promise.all((nextOrder.authorizations || []).map(async authUrl => ({
      ...(await client.getAuthorization(authUrl)),
      url: authUrl,
    })));
    setOrder(nextOrder);
    setAuthorizations(auths);
    setCertificate(nextOrder.certificate
      ? await client.getCertificate(nextOrder.certificate)
      : '');
    return nextOrder;
  }

  async function createOrder(event) {
    event.preventDefault();
    await run(async () => {
      const domains = normalizeDomains(domainInput);
      if (!domains.length) throw new Error('Enter at least one domain');
      setSelected({});
      setCertificate('');
      const keyPair = await generateKeyPair();
      const request = await createCSR(keyPair, domains);
      const privateKey = await exportPrivateKey(keyPair);
      const nextOrder = await client.createOrder({ identifiers: domains.map(value => ({ type: 'dns', value })) });
      if (!nextOrder.url) throw new Error('ACME server did not return an order URL');
      setCertificateKey(privateKey);
      setCsr(request);
      setOrderUrl(nextOrder.url);
      await refreshOrder(nextOrder.url);
    });
  }

  async function chooseChallenge(auth, challenge) {
    await run(async () => {
      const challengeKey = await client.getChallengeKey(challenge);
      let instruction;
      if (challenge.type === 'http-01') {
        instruction = {
          label: 'Serve this exact content over HTTP',
          name: `http://${auth.identifier.value}/.well-known/acme-challenge/${challenge.token}`,
          value: challengeKey,
        };
      } else if (challenge.type === 'dns-01') {
        instruction = {
          label: 'Create this DNS TXT record',
          name: `_acme-challenge.${auth.identifier.value}`,
          value: challengeKey,
        };
      } else {
        throw new Error(`Unsupported challenge: ${challenge.type}`);
      }
      setSelected(current => ({ ...current, [auth.url]: { challenge, instruction } }));
    });
  }

  async function verifyChallenge(challenge) {
    await run(async () => {
      await client.respondToChallenge(challenge.url);
      await refreshOrder();
    });
  }

  async function finalize() {
    await run(async () => {
      if (!csr) throw new Error('CSR is missing');
      await client.finalizeOrder(order.finalize, csr.der);
      let current;
      for (let attempt = 0; attempt < 8; attempt++) {
        current = await refreshOrder();
        if (current.status === 'valid' || current.status === 'invalid') break;
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    });
  }

  const ready = order?.status === 'ready';
  const allValid = authorizations.length > 0 && authorizations.every(auth => auth.status === 'valid');

  return html`
    <header>
      <h1>🔒 Greenlock</h1>
      <p>Issue a Let’s Encrypt certificate entirely in your browser. No server, no build step, no private-key upload.</p>
    </header>

    ${error && html`<p class="error"><strong>Error:</strong> ${error}</p>`}

    <section>
      <h2>1. Account</h2>
      <label>
        Certificate authority
        <select value=${directoryUrl} disabled=${busy} onChange=${event => setDirectoryUrl(event.target.value)}>
          ${PROVIDERS.map(([name, url]) => html`<option value=${url}>${name}</option>`)}
        </select>
      </label>
      ${directory
        ? html`<p class="muted">Directory loaded.${directory.meta?.termsOfService && html` <a href=${directory.meta.termsOfService} target="_blank" rel="noreferrer">Terms of Service</a>`}</p>`
        : html`<p class="muted">Loading ACME directory…</p>`}

      ${!accountUrl ? html`
        <form onSubmit=${createAccount}>
          <label>
            Email
            <input type="email" required value=${email} disabled=${busy || !directory}
              onInput=${event => setEmail(event.target.value)} placeholder="you@example.com">
          </label>
          <button disabled=${busy || !directory}>Create ACME account</button>
          <small>Creating the account means you agree to the CA terms linked above.</small>
        </form>
      ` : html`
        <p class="status">✓ Account ready</p>
        <code>${accountUrl}</code>
        <p><button class="secondary" onClick=${() => download('greenlock-account-key.pem', accountKey)}>Download account key</button></p>
      `}
    </section>

    <section>
      <h2>2. Certificate</h2>
      <form onSubmit=${createOrder}>
        <label>
          Domains
          <textarea rows="3" required disabled=${busy || !accountUrl}
            value=${domainInput} onInput=${event => setDomainInput(event.target.value)}
            placeholder="example.com\nwww.example.com"></textarea>
        </label>
        <button disabled=${busy || !accountUrl}>Create order</button>
        <small>Separate domains with spaces, commas, or new lines. Wildcards are supported and require DNS validation.</small>
      </form>
      ${order && html`<p class="status">Order: <strong>${order.status}</strong> <button class="link" disabled=${busy} onClick=${() => run(() => refreshOrder())}>refresh</button></p>`}
    </section>

    ${authorizations.length > 0 && html`
      <section>
        <h2>3. Validate domains</h2>
        ${authorizations.map(auth => {
          const choice = selected[auth.url];
          const supported = auth.challenges.filter(item => item.type === 'http-01' || item.type === 'dns-01');
          return html`
            <article>
              <p><strong>${auth.identifier.value}</strong> <span class="badge">${auth.status}</span></p>
              ${auth.status !== 'valid' && html`
                <div class="row">
                  ${supported.map(challenge => html`
                    <button class="secondary" disabled=${busy} onClick=${() => chooseChallenge(auth, challenge)}>${challenge.type}</button>
                  `)}
                </div>
                ${choice && html`
                  <div class="instruction">
                    <p>${choice.instruction.label}:</p>
                    <code>${choice.instruction.name}</code>
                    <pre>${choice.instruction.value}</pre>
                    <button disabled=${busy} onClick=${() => verifyChallenge(choice.challenge)}>I’ve configured it — verify</button>
                  </div>
                `}
              `}
            </article>
          `;
        })}
      </section>
    `}

    ${order && (ready || allValid || order.status === 'processing' || order.status === 'valid') && html`
      <section>
        <h2>4. Issue</h2>
        ${order.status === 'valid' ? html`
          <p class="status">✓ Certificate issued</p>
        ` : html`
          <p class="muted">All authorizations are complete. Finalize the order with the CSR generated in this browser.</p>
          <button disabled=${busy || !ready} onClick=${finalize}>Issue certificate</button>
          ${!ready && html`<small>Order status is ${order.status}; refresh until it becomes ready.</small>`}
        `}
      </section>
    `}

    ${certificate && html`
      <section>
        <h2>5. Download</h2>
        <p class="status">Keep the private key secret. Greenlock does not persist it.</p>
        <div class="row">
          <button onClick=${() => download('certificate.pem', certificate)}>Certificate</button>
          <button class="secondary" onClick=${() => download('private-key.pem', certificateKey)}>Private key</button>
          <button class="secondary" onClick=${() => download('request.csr', csr.pem)}>CSR</button>
        </div>
        <details>
          <summary>Certificate PEM</summary>
          <pre>${certificate}</pre>
        </details>
      </section>
    `}

    <footer>
      <small>Cryptographic keys are generated with Web Crypto and remain in this tab unless you download them.</small>
    </footer>
  `;
}

render(html`<${App} />`, document.getElementById('app'));
